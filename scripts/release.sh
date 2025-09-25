#!/bin/bash

# scripts/release.sh - Automated release script for ExposeME
# Usage: ./scripts/release.sh 1.5.0

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Helper functions
error() {
    echo -e "${RED}❌ ERROR: $1${NC}" >&2
    exit 1
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

bold() {
    echo -e "${BOLD}$1${NC}"
}

# Check if version parameter is provided
if [ $# -eq 0 ]; then
    error "Version parameter is required!\n\nUsage: $0 <version>\nExample: $0 1.5.0"
fi

VERSION=$1
TAG="v${VERSION}"

# Validate version format (semantic versioning)
validate_version() {
    local version_regex="^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?(\+[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$"

    if [[ ! $VERSION =~ $version_regex ]]; then
        error "Invalid version format: $VERSION\n\nValid formats:\n  • 1.0.0\n  • 2.1.3\n  • 1.0.0-beta.1\n  • 1.0.0+build.1"
    fi

    success "Version format is valid: $VERSION"
}

# Check if we're in a git repository
check_git_repo() {
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        error "Not in a git repository!"
    fi
    success "Git repository detected"
}

# Check if working directory is clean
check_working_directory() {
    if ! git diff --quiet; then
        warning "Working directory has uncommitted changes!"
        echo -e "\nUncommitted changes:"
        git diff --name-only
        echo ""
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error "Release cancelled due to uncommitted changes"
        fi
    else
        success "Working directory is clean"
    fi
}

# Check if tag already exists
check_existing_tag() {
    if git tag -l | grep -q "^${TAG}$"; then
        error "Tag $TAG already exists!\n\nExisting tags:"$(git tag -l | tail -5 | sed 's/^/\n  • /')
    fi
    success "Tag $TAG is available"
}

# Check if required files exist
check_required_files() {
    local missing_files=()

    if [[ ! -f "Cargo.toml" ]]; then
        missing_files+=("Cargo.toml")
    fi

    if [[ ! -f "ui/Cargo.toml" ]]; then
        missing_files+=("ui/Cargo.toml")
    fi

    if [[ ! -d ".github/workflows" ]]; then
        missing_files+=(".github/workflows (directory)")
    fi

    if [ ${#missing_files[@]} -ne 0 ]; then
        error "Missing required files:\n$(printf "  • %s\n" "${missing_files[@]}")"
    fi

    success "All required files found"
}

# Check if we can push to remote
check_remote_access() {
    local remote_url=$(git remote get-url origin 2>/dev/null || echo "")
    if [[ -z "$remote_url" ]]; then
        error "No remote origin configured!"
    fi

    info "Remote origin: $remote_url"

    # Test if we can fetch (basic connectivity check)
    if ! git ls-remote --heads origin >/dev/null 2>&1; then
        error "Cannot access remote repository. Check your internet connection and git credentials."
    fi

    success "Remote access verified"
}

# Update version in Cargo.toml files
update_cargo_version() {
    info "Updating version in Cargo.toml files..."

    # Update workspace version
    cargo set-version --workspace "$VERSION"

    # Verify the changes were made
    local root_version=$(grep "^version = " Cargo.toml | head -1 | cut -d'"' -f2)
    local ui_version=$(grep "^version = " ui/Cargo.toml | head -1 | cut -d'"' -f2)

    if [[ "$root_version" != "$VERSION" ]]; then
        error "Failed to update version in root Cargo.toml (got: $root_version, expected: $VERSION)"
    fi

    if [[ "$ui_version" != "$VERSION" ]]; then
        error "Failed to update version in ui/Cargo.toml (got: $ui_version, expected: $VERSION)"
    fi

    success "Updated Cargo.toml files to version $VERSION"
}

# Update Cargo.lock file
update_cargo_lock() {
    info "Updating Cargo.lock..."

    if command -v cargo >/dev/null 2>&1; then
        cargo check --quiet 2>/dev/null || warning "Cargo check failed, but continuing..."
        success "Cargo.lock updated"
    else
        warning "Cargo not found, Cargo.lock may be outdated"
    fi
}

# Commit changes
commit_changes() {
    info "Committing version bump..."

    git add Cargo.toml ui/Cargo.toml Cargo.lock
    git commit -m "chore: bump version to $VERSION

- Updated root Cargo.toml to $VERSION
- Updated ui/Cargo.toml to $VERSION
- Prepared for release $TAG"

    success "Committed version bump"
}

# Create and push tag
create_and_push_tag() {
    info "Creating tag $TAG..."

    git tag -a "$TAG" -m "Release $TAG

$(date '+%Y-%m-%d %H:%M:%S')

Changes:
- Version bumped to $VERSION
- All binaries include Web UI Dashboard
- Cross-platform releases for Linux, Windows, macOS
- Docker images with UI included

To download: https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\([^/]*\/[^/]*\).git.*/\1/')/releases/tag/$TAG"

    success "Created tag $TAG"
}

# Push changes
push_changes() {
    info "Pushing changes and tag to remote..."

    local current_branch=$(git branch --show-current)
    git push origin "$current_branch"
    git push origin "$TAG"

    success "Pushed changes and tag to remote"
}

# Show release information
show_release_info() {
    local repo_url=$(git remote get-url origin | sed 's/\.git$//' | sed 's/git@github\.com:/https:\/\/github\.com\//')

    echo
    bold "🚀 RELEASE INITIATED SUCCESSFULLY!"
    echo
    info "Version: $VERSION"
    info "Tag: $TAG"
    info "Repository: $repo_url"
    echo
    info "GitHub Actions will now:"
    echo "  • Build binaries for Linux, Windows, macOS (with UI)"
    echo "  • Create Docker images (with UI)"
    echo "  • Publish to GitHub Container Registry"
    echo "  • Create GitHub Release with all assets"
    echo
    info "Monitor progress:"
    echo "  • Actions: $repo_url/actions"
    echo "  • Release: $repo_url/releases/tag/$TAG (available in ~10-15 minutes)"
    echo "  • Packages: $repo_url/packages"
    echo
    success "Release $TAG is now building! 🎉"
}

# Main execution
main() {
    bold "🏷️  EXPOSEME RELEASE SCRIPT"
    echo "═══════════════════════════════════════"
    echo
    info "Preparing release for version $VERSION..."
    echo

    # Run all checks
    validate_version
    check_git_repo
    check_required_files
    check_working_directory
    check_existing_tag
    check_remote_access

    echo
    warning "This will:"
    echo "  • Update Cargo.toml files to version $VERSION"
    echo "  • Commit the changes"
    echo "  • Create tag $TAG"
    echo "  • Push to remote origin"
    echo "  • Trigger GitHub Actions release workflow"
    echo
    read -p "Continue? (y/N): " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Release cancelled by user"
        exit 0
    fi

    echo
    info "Starting release process..."
    echo

    # Execute release steps
    update_cargo_version
    update_cargo_lock
    commit_changes
    create_and_push_tag
    push_changes

    echo
    show_release_info
}

# Run main function
main "$@"