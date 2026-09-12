"""Memory - Task history, script reuse, and pattern matching.

Provides the Agent with memory of past tasks, successful scripts,
and discovered hook points for knowledge reuse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fridapilot.storage.db import Database


@dataclass
class MemoryMatch:
    """A matched historical record."""
    source: str  # "task" | "script" | "hook_point"
    score: float  # Relevance score 0-1
    data: dict[str, Any] = field(default_factory=dict)


class Memory:
    """Agent memory backed by SQLite storage.

    Enables:
    - "Last time I hooked this app, what worked?"
    - "Reuse the script that succeeded for this target."
    - "What hook points were discovered for this app?"
    """

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or Database()

    def recall_tasks(self, target: str = "", limit: int = 5) -> list[MemoryMatch]:
        """Recall past tasks for a target."""
        tasks = self.db.list_tasks(target=target, limit=limit)
        return [
            MemoryMatch(
                source="task",
                score=1.0 if t["status"] == "completed" else 0.3,
                data=t,
            )
            for t in tasks
        ]

    def recall_scripts(self, target: str = "", platform: str = "",
                       tags: str = "") -> list[MemoryMatch]:
        """Recall scripts that worked for a target/platform."""
        scripts = self.db.find_scripts(target=target, platform=platform, tags=tags)
        return [
            MemoryMatch(source="script", score=0.8, data=s)
            for s in scripts
        ]

    def recall_hook_points(self, target: str) -> list[MemoryMatch]:
        """Recall discovered hook points for a target."""
        hooks = self.db.find_hook_points(target=target)
        return [
            MemoryMatch(source="hook_point", score=0.7, data=h)
            for h in hooks
        ]

    def search(self, query: str, target: str = "", limit: int = 10) -> list[MemoryMatch]:
        """Search memory for relevant past knowledge.

        Simple keyword matching across tasks, scripts, and hook points.
        """
        results: list[MemoryMatch] = []
        query_lower = query.lower()

        # Search tasks
        for task in self.db.list_tasks(target=target, limit=50):
            if query_lower in task.get("goal", "").lower():
                score = 1.0 if task["status"] == "completed" else 0.3
                results.append(MemoryMatch(source="task", score=score, data=task))

        # Search scripts
        for script in self.db.find_scripts(target=target, limit=50):
            if (query_lower in script.get("name", "").lower()
                    or query_lower in script.get("tags", "").lower()):
                results.append(MemoryMatch(source="script", score=0.8, data=script))

        # Sort by score descending
        results.sort(key=lambda m: m.score, reverse=True)
        return results[:limit]

    def save_task_result(
        self,
        task_id: int,
        success: bool,
        report: str = "",
        scripts: list[dict] | None = None,
        hook_points: list[dict] | None = None,
        messages: list[dict] | None = None,
    ) -> None:
        """Persist a completed task's results for future recall."""
        self.db.finish_task(task_id, "completed" if success else "failed", report)

        if scripts:
            for s in scripts:
                self.db.save_script(
                    name=s.get("name", "unnamed"),
                    source=s.get("source", ""),
                    target=s.get("target", ""),
                    platform=s.get("platform", ""),
                    tags=s.get("tags", ""),
                    task_id=task_id,
                )

        if hook_points:
            for hp in hook_points:
                self.db.save_hook_point(
                    target=hp.get("target", ""),
                    platform=hp.get("platform", ""),
                    class_name=hp.get("class_name", ""),
                    method_name=hp.get("method_name", ""),
                    module_name=hp.get("module_name", ""),
                    address=hp.get("address", ""),
                    description=hp.get("description", ""),
                )

        if messages:
            self.db.save_messages(task_id, messages)

    def get_context_for_planner(self, target: str, goal: str = "") -> str:
        """Build a context string for the LLM planner from memory.

        Returns a summary of relevant past tasks, scripts, and hook points
        that helps the planner make better decisions.
        """
        parts: list[str] = []

        # Past tasks
        tasks = self.recall_tasks(target=target, limit=3)
        if tasks:
            parts.append("Past tasks for this target:")
            for m in tasks:
                t = m.data
                parts.append(f"  - [{t.get('status')}] {t.get('goal')} (id={t.get('id')})")

        # Known scripts
        scripts = self.recall_scripts(target=target)
        if scripts:
            parts.append("Known scripts:")
            for m in scripts:
                s = m.data
                parts.append(f"  - {s.get('name')} [{s.get('platform')}] tags={s.get('tags')}")

        # Known hook points
        hooks = self.recall_hook_points(target=target)
        if hooks:
            parts.append(f"Known hook points ({len(hooks)}):")
            for m in hooks[:10]:
                hp = m.data
                if hp.get("class_name"):
                    parts.append(f"  - {hp['class_name']}.{hp.get('method_name','*')}")
                elif hp.get("module_name"):
                    parts.append(f"  - {hp['module_name']}!{hp.get('address','')}")

        return "\n".join(parts) if parts else "No prior knowledge for this target."
