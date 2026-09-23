from dataclasses import dataclass, field

@dataclass
class ResourceGraph:
    touched: set[str] = field(default_factory=set)
    modified: set[str] = field(default_factory=set)
    external: set[str] = field(default_factory=set)

    def record(self, resource: str, *, modified: bool = False, external: bool = False) -> None:
        self.touched.add(resource)
        if modified:
            self.modified.add(resource)
        if external:
            self.external.add(resource)

    def summary(self) -> dict[str, int]:
        return {"touched": len(self.touched), "modified": len(self.modified), "external": len(self.external)}
