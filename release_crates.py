#!/usr/bin/env python3
"""
Automated crate release script for the librustzcash workspace.

This script releases crates in dependency order, performing version updates,
updating CHANGELOGs, and creating release commits.
"""

import json
import subprocess
import sys
import re
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Set, Optional
from datetime import datetime

try:
    import marko
    from marko import block, inline
except ImportError:
    print("Error: marko library not found. Please install it with: pip install marko", file=sys.stderr)
    sys.exit(1)


@dataclass
class CrateInfo:
    name: str
    version: str
    manifest_path: str
    dependencies: Set[str]


class ChangelogParser:
    """Helper class for parsing and updating changelog files."""
    
    def __init__(self, content: str):
        self.content = content
        self.doc = marko.parse(content)
    
    def find_heading(self, heading_text: str, level: int = 2) -> Optional[int]:
        """Find the index of a heading in the document."""
        for i, child in enumerate(self.doc.children):
            if isinstance(child, block.Heading) and child.level == level:
                text = self._extract_text(child)
                if heading_text in text:
                    return i
        return None
    
    def _extract_text(self, element) -> str:
        """Extract plain text from a markdown element."""
        if hasattr(element, 'children'):
            return ''.join(self._extract_text(child) for child in element.children)
        elif hasattr(element, 'content'):
            return element.content
        else:
            return str(element)
    
    def _create_heading(self, text: str, level: int) -> block.Heading:
        """Create a new heading element."""
        heading = block.Heading(level=level)
        heading.children = [inline.RawText(content=text)]
        return heading
    
    def _create_paragraph(self, text: str = "") -> block.Paragraph:
        """Create a new paragraph element."""
        para = block.Paragraph()
        if text:
            para.children = [inline.RawText(content=text)]
        else:
            para.children = []
        return para
    
    def update_planned_to_date(self, version: str, date: str) -> bool:
        """Update a PLANNED version to have an actual date."""
        pattern = f"[{version}] - PLANNED"
        replacement = f"[{version}] - {date}"
        
        for child in self.doc.children:
            if isinstance(child, block.Heading) and child.level == 2:
                text = self._extract_text(child)
                if pattern in text:
                    # Update the heading text
                    new_text = text.replace(pattern, replacement)
                    child.children = [inline.RawText(content=new_text)]
                    return True
        return False
    
    def ensure_version_section(self, version: str, date: str) -> bool:
        """Ensure a version section exists, creating it if necessary."""
        # First try to update existing PLANNED section
        if self.update_planned_to_date(version, date):
            return True
        
        # Check if version section already exists
        version_pattern = f"[{version}]"
        if self.find_heading(version_pattern, 2) is not None:
            return True
        
        # Create new version section after Unreleased
        unreleased_idx = self.find_heading("Unreleased", 2)
        insert_idx = 0
        
        if unreleased_idx is not None:
            # Find the next heading after Unreleased, or end of document
            insert_idx = unreleased_idx + 1
            while (insert_idx < len(self.doc.children) and
                   not (isinstance(self.doc.children[insert_idx], block.Heading) and
                        self.doc.children[insert_idx].level == 2)):
                insert_idx += 1
        
        # Create new version heading
        version_heading = self._create_heading(f"[{version}] - {date}", 2)
        
        # Insert empty paragraph and Changes heading
        empty_para = self._create_paragraph()
        changes_heading = self._create_heading("Changes", 3)
        changes_para = self._create_paragraph()
        
        # Insert in reverse order to maintain indices
        self.doc.children.insert(insert_idx, changes_para)
        self.doc.children.insert(insert_idx, changes_heading)
        self.doc.children.insert(insert_idx, empty_para)
        self.doc.children.insert(insert_idx, version_heading)
        
        return True
    
    def find_changes_section_for_version(self, version: str) -> Optional[int]:
        """Find the Changes section index for a given version."""
        version_idx = self.find_heading(f"[{version}]", 2)
        if version_idx is None:
            return None
        
        # Look for ### Changes after the version heading
        for i in range(version_idx + 1, len(self.doc.children)):
            child = self.doc.children[i]
            if isinstance(child, block.Heading):
                if child.level == 2:
                    # Hit another version section
                    break
                elif child.level == 3:
                    text = self._extract_text(child)
                    if "Changes" in text:
                        return i
        return None
    
    def ensure_changes_section(self, version: str):
        """Ensure a Changes section exists for the given version."""
        if self.find_changes_section_for_version(version) is not None:
            return  # Already exists
        
        version_idx = self.find_heading(f"[{version}]", 2)
        if version_idx is None:
            return
        
        # Insert Changes section after version heading
        insert_idx = version_idx + 1
        
        # Skip any existing content until we find the next heading or end
        while (insert_idx < len(self.doc.children) and
               not (isinstance(self.doc.children[insert_idx], block.Heading) and
                    self.doc.children[insert_idx].level <= 3)):
            insert_idx += 1
        
        changes_heading = self._create_heading("Changes", 3)
        changes_para = self._create_paragraph()
        
        self.doc.children.insert(insert_idx, changes_para)
        self.doc.children.insert(insert_idx, changes_heading)
    
    def add_or_update_migration_line(self, version: str, crate_name: str, crate_version: str):
        """Add or update a migration line in the Changes section."""
        self.ensure_changes_section(version)
        
        changes_idx = self.find_changes_section_for_version(version)
        if changes_idx is None:
            return
        
        migration_text = f"- Migrated to `{crate_name} {crate_version}`"
        
        # Look for existing migration line or place to insert
        for i in range(changes_idx + 1, len(self.doc.children)):
            child = self.doc.children[i]
            
            # Stop at next heading
            if isinstance(child, block.Heading):
                # Insert new list item before this heading
                list_item = block.ListItem()
                list_item.children = [block.Paragraph()]
                list_item.children[0].children = [inline.RawText(content=f"Migrated to `{crate_name} {crate_version}`")]
                
                # Create list if needed
                if i > 0 and not isinstance(self.doc.children[i-1], block.List):
                    new_list = block.List(ordered=False)
                    new_list.children = [list_item]
                    self.doc.children.insert(i, new_list)
                else:
                    self.doc.children[i-1].children.append(list_item)
                break
            
            # Check if this is a list with migration items
            elif isinstance(child, block.List):
                # Look for existing migration line for this crate
                found_existing = False
                for list_item in child.children:
                    if isinstance(list_item, block.ListItem):
                        item_text = self._extract_text(list_item)
                        if f"Migrated to" in item_text and crate_name in item_text:
                            # Update existing item
                            list_item.children[0].children = [inline.RawText(content=f"Migrated to `{crate_name} {crate_version}`")]
                            found_existing = True
                            break
                
                if not found_existing:
                    # Add new item to existing list
                    new_item = block.ListItem()
                    new_item.children = [block.Paragraph()]
                    new_item.children[0].children = [inline.RawText(content=f"Migrated to `{crate_name} {crate_version}`")]
                    child.children.append(new_item)
                break
    
    def render(self) -> str:
        """Render the document back to markdown."""
        return marko.render(self.doc)


class WorkspaceReleaser:
    def __init__(self, workspace_root: str = "."):
        self.workspace_root = Path(workspace_root).resolve()
        self.crates: Dict[str, CrateInfo] = {}
        self.load_workspace_metadata()
    
    def load_workspace_metadata(self):
        """Load workspace metadata using cargo metadata."""
        cmd = ["cargo", "metadata", "--format-version", "1", "--no-deps"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.workspace_root)
        
        if result.returncode != 0:
            print(f"Error running cargo metadata: {result.stderr}", file=sys.stderr)
            sys.exit(1)
        
        metadata = json.loads(result.stdout)
        workspace_members = set(metadata["workspace_members"])
        
        for package in metadata["packages"]:
            package_id = f"{package['name']} {package['version']} (path+file://{package['manifest_path'].replace('/Cargo.toml', '')})"
            
            if package_id in workspace_members:
                # Extract workspace dependencies
                deps = set()
                for dep in package.get("dependencies", []):
                    dep_name = dep["name"]
                    # Only include workspace dependencies
                    if any(p["name"] == dep_name for p in metadata["packages"] 
                           if f"{p['name']} {p['version']} (path+file://{p['manifest_path'].replace('/Cargo.toml', '')})" in workspace_members):
                        deps.add(dep_name)
                
                self.crates[package["name"]] = CrateInfo(
                    name=package["name"],
                    version=package["version"],
                    manifest_path=package["manifest_path"],
                    dependencies=deps
                )
    
    def topological_sort(self) -> List[str]:
        """Sort crates in dependency order using topological sort."""
        # Build reverse dependency graph (dependents)
        dependents: Dict[str, Set[str]] = {name: set() for name in self.crates}
        
        for crate_name, crate_info in self.crates.items():
            for dep in crate_info.dependencies:
                if dep in dependents:
                    dependents[dep].add(crate_name)
        
        # Topological sort using Kahn's algorithm
        in_degree = {name: len(info.dependencies) for name, info in self.crates.items()}
        queue = [name for name, degree in in_degree.items() if degree == 0]
        result = []
        
        while queue:
            current = queue.pop(0)
            result.append(current)
            
            for dependent in dependents[current]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)
        
        if len(result) != len(self.crates):
            remaining = [name for name, degree in in_degree.items() if degree > 0]
            print(f"Circular dependency detected among: {remaining}", file=sys.stderr)
            sys.exit(1)
        
        return result
    
    def bump_version(self, version: str, bump_type: str = "patch") -> str:
        """Bump a semantic version."""
        major, minor, patch = map(int, version.split('.'))
        
        if bump_type == "major":
            return f"{major + 1}.0.0"
        elif bump_type == "minor":
            return f"{major}.{minor + 1}.0"
        else:  # patch
            return f"{major}.{minor}.{patch + 1}"
    
    def update_crate_toml(self, crate_name: str, new_version: str):
        """Update the version in a crate's Cargo.toml."""
        manifest_path = Path(self.crates[crate_name].manifest_path)
        
        with open(manifest_path, 'r') as f:
            content = f.read()
        
        # Update version field
        content = re.sub(
            r'version\s*=\s*"[^"]*"',
            f'version = "{new_version}"',
            content,
            count=1
        )
        
        with open(manifest_path, 'w') as f:
            f.write(content)
    
    def update_workspace_toml(self, crate_name: str, new_version: str):
        """Update the version in workspace Cargo.toml dependencies."""
        workspace_toml = self.workspace_root / "Cargo.toml"
        
        with open(workspace_toml, 'r') as f:
            content = f.read()
        
        # Find and update the workspace dependency entry
        pattern = rf'{re.escape(crate_name)}\s*=\s*{{\s*version\s*=\s*"[^"]*"'
        replacement = f'{crate_name} = {{ version = "{new_version}"'
        content = re.sub(pattern, replacement, content)
        
        with open(workspace_toml, 'w') as f:
            f.write(content)
    
    def update_changelog(self, crate_name: str, new_version: str):
        """Update the CHANGELOG.md for a crate."""
        crate_dir = Path(self.crates[crate_name].manifest_path).parent
        changelog_path = crate_dir / "CHANGELOG.md"
        
        if not changelog_path.exists():
            print(f"Warning: No CHANGELOG.md found for {crate_name}")
            return
        
        with open(changelog_path, 'r') as f:
            content = f.read()
        
        today = datetime.now().strftime("%Y-%m-%d")
        
        # Use the changelog parser to handle the update
        parser = ChangelogParser(content)
        parser.ensure_version_section(new_version, today)
        
        with open(changelog_path, 'w') as f:
            f.write(parser.render())
    
    def update_dependent_changelogs(self, crate_name: str, new_version: str):
        """Update CHANGELOGs of crates that depend on the released crate."""
        dependents = []
        for name, crate_info in self.crates.items():
            if crate_name in crate_info.dependencies:
                dependents.append(name)
        
        for dependent in dependents:
            crate_dir = Path(self.crates[dependent].manifest_path).parent
            changelog_path = crate_dir / "CHANGELOG.md"
            
            if not changelog_path.exists():
                continue
            
            with open(changelog_path, 'r') as f:
                content = f.read()
            
            # Use the changelog parser to handle the update
            parser = ChangelogParser(content)
            
            # Find the current version of the dependent crate for the changelog entry
            dependent_version = self.crates[dependent].version
            
            # Ensure the dependent has a version section and Changes subsection
            parser.ensure_version_section(dependent_version, "PLANNED")
            parser.add_or_update_migration_line(dependent_version, crate_name, new_version)
            
            with open(changelog_path, 'w') as f:
                f.write(parser.render())
    
    def update_supply_chain(self, crate_name: str, new_version: str):
        """Update supply chain metadata using cargo vet."""
        cmd = ["cargo", "vet"]
        result = subprocess.run(cmd, cwd=self.workspace_root, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Warning: cargo vet failed: {result.stderr}", file=sys.stderr)
            # Continue anyway as this might not be critical for the release
    
    def run_cargo_update(self):
        """Run cargo check to perform minimal required updates to Cargo.lock."""
        cmd = ["cargo", "check", "--tests", "--all-features"]
        result = subprocess.run(cmd, cwd=self.workspace_root)
        if result.returncode != 0:
            print("Error running cargo check", file=sys.stderr)
            sys.exit(1)
    
    def validate_release(self, crate_name: str, new_version: str) -> bool:
        """Validate the release using cargo publish --dry-run and cargo semver-checks."""
        print(f"  Validating release for {crate_name}...")
        
        # Run cargo publish --dry-run
        print(f"  Running cargo publish --dry-run for {crate_name}...")
        cmd = ["cargo", "publish", "-p", crate_name, "--dry-run"]
        result = subprocess.run(cmd, cwd=self.workspace_root, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error: cargo publish --dry-run failed for {crate_name}:", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            return False
        
        # Run cargo semver-checks
        print(f"  Running cargo semver-checks for {crate_name}...")
        cmd = ["cargo", "semver-checks", "check-release", "-p", crate_name]
        result = subprocess.run(cmd, cwd=self.workspace_root, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error: cargo semver-checks failed for {crate_name}:", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            print(f"Consider using a different version bump type (--bump major/minor/patch)", file=sys.stderr)
            return False
        
        print(f"  ✓ Validation passed for {crate_name}")
        return True
    
    def create_commit(self, crate_name: str, new_version: str):
        """Create a git commit for the release."""
        commit_message = f"Release {crate_name} version {new_version}"
        
        cmd = ["git", "add", "-A"]
        subprocess.run(cmd, cwd=self.workspace_root)
        
        cmd = ["git", "commit", "-m", commit_message]
        result = subprocess.run(cmd, cwd=self.workspace_root)
        
        if result.returncode != 0:
            print(f"Error creating commit for {crate_name}", file=sys.stderr)
            sys.exit(1)
        
        print(f"✓ Created commit: {commit_message}")
    
    def release_crate(self, crate_name: str, bump_type: str = "patch"):
        """Release a single crate."""
        if crate_name not in self.crates:
            print(f"Error: Crate '{crate_name}' not found in workspace", file=sys.stderr)
            return False
        
        current_version = self.crates[crate_name].version
        new_version = self.bump_version(current_version, bump_type)
        
        print(f"Releasing {crate_name}: {current_version} -> {new_version}")
        
        # Update versions and files
        self.update_crate_toml(crate_name, new_version)
        self.update_workspace_toml(crate_name, new_version)
        self.update_changelog(crate_name, new_version)
        self.update_dependent_changelogs(crate_name, new_version)
        self.update_supply_chain(crate_name, new_version)
        
        # Update Cargo.lock
        self.run_cargo_update()
        
        # Validate the release before committing
        if not self.validate_release(crate_name, new_version):
            print(f"Release validation failed for {crate_name}", file=sys.stderr)
            return False
        
        # Create commit
        self.create_commit(crate_name, new_version)
        
        # Update our internal version tracking
        self.crates[crate_name].version = new_version
        
        return True
    
    def release_all(self, bump_type: str = "patch", exclude: Optional[List[str]] = None):
        """Release all crates in dependency order."""
        exclude = exclude or []
        release_order = self.topological_sort()
        
        print("Release order:", " -> ".join(release_order))
        print()
        
        for crate_name in release_order:
            if crate_name in exclude:
                print(f"Skipping {crate_name} (excluded)")
                continue
            
            if not self.release_crate(crate_name, bump_type):
                return False
        
        return True


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Release crates in dependency order")
    parser.add_argument("--crate", help="Release specific crate only")
    parser.add_argument("--bump", choices=["major", "minor", "patch"], default="patch",
                        help="Version bump type (default: patch)")
    parser.add_argument("--exclude", nargs="*", default=[],
                        help="Crates to exclude from release")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show release order without making changes")
    
    args = parser.parse_args()
    
    releaser = WorkspaceReleaser()
    
    if args.dry_run:
        release_order = releaser.topological_sort()
        print("Release order:", " -> ".join(release_order))
        return
    
    if args.crate:
        success = releaser.release_crate(args.crate, args.bump)
    else:
        success = releaser.release_all(args.bump, args.exclude)
    
    if success:
        print("\n✓ All releases completed successfully!")
    else:
        print("\n✗ Release failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
