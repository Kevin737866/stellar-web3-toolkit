#!/bin/bash
# create-pr.sh - Script to create a pull request for the Stellar Payment Channel Network implementation

# Configuration
REPO_OWNER="Kevin737866"
REPO_NAME="stellar-web3-toolkit"
BASE_BRANCH="main"
HEAD_BRANCH="feature/payment-channels"
PR_TITLE="feat: Implement Lightning Network-style payment channels on Stellar"
PR_BODY_FILE=".github/PULL_REQUEST_TEMPLATE.md"

# GitHub API endpoint
GITHUB_API="https://api.github.com"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Stellar Payment Channel Network - Pull Request Creator${NC}\n"

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo -e "${RED}Error: GitHub CLI (gh) is not installed${NC}"
    echo "Install it from: https://cli.github.com/"
    exit 1
fi

# Check authentication
echo -e "${YELLOW}Checking GitHub authentication...${NC}"
if ! gh auth status &> /dev/null; then
    echo -e "${RED}Error: Not authenticated with GitHub${NC}"
    echo "Run 'gh auth login' to authenticate"
    exit 1
fi

echo -e "${GREEN}Authenticated successfully${NC}\n"

# Get PR body from template
if [ -f "$PR_BODY_FILE" ]; then
    PR_BODY=$(cat "$PR_BODY_FILE")
else
    PR_BODY="## Summary

Implementing a Lightning Network-style payment channel system on Stellar for instant, low-cost off-chain transactions with on-chain settlement.

### Features Implemented:
- Multi-sig escrow account structure
- Channel opening (funding transaction)
- Off-chain payment state updates in Rust
- Multi-hop payment routing algorithm (Dijkstra's, A*, BFS)
- Cooperative channel closing
- Unilateral close with dispute period
- Watchtower service for monitoring
- Channel rebalancing mechanism
- HTLC for multi-hop payments
- Formal specification (SPEC.md)
- Network simulation with 100+ nodes"
fi

# Check if branch exists
echo -e "${YELLOW}Checking branch status...${NC}"
if git rev-parse "$HEAD_BRANCH" &> /dev/null; then
    echo -e "${GREEN}Branch '$HEAD_BRANCH' exists locally${NC}"
else
    echo -e "${YELLOW}Creating branch '$HEAD_BRANCH'...${NC}"
    git checkout -b "$HEAD_BRANCH"
fi

# Ensure we're on the right branch
git checkout "$HEAD_BRANCH"

# Stage all changes
echo -e "${YELLOW}Staging changes...${NC}"
git add -A

# Commit if there are changes
if git diff --cached --quiet; then
    echo -e "${YELLOW}No changes to commit${NC}"
else
    echo -e "${YELLOW}Committing changes...${NC}"
    git commit -m "feat: Implement Lightning Network-style payment channels

- Add Soroban smart contract for payment channels
- Implement multi-hop routing with Dijkstra/A*/BFS algorithms
- Add watchtower service for breach detection
- Create 100+ node network simulator
- Write formal specification (SPEC.md)
- Add GitHub Actions CI/CD pipeline

Closes #4"
fi

# Push branch to remote
echo -e "${YELLOW}Pushing branch to remote...${NC}"
git push -u origin "$HEAD_BRANCH" 2>/dev/null

# Create pull request using gh CLI
echo -e "${YELLOW}Creating pull request...${NC}"
gh pr create \
    --title "$PR_TITLE" \
    --body "$PR_BODY" \
    --base "$BASE_BRANCH" \
    --head "$HEAD_BRANCH" \
    --assignee "@me" \
    --label "payment-channels,stellar,soroban,layer2"

echo -e "\n${GREEN}Pull request created successfully!${NC}"
echo -e "View it at: https://github.com/$REPO_OWNER/$REPO_NAME/pull/new/$HEAD_BRANCH"
