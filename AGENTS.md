# Merge Prohibition

- Never merge pull requests, stacks, or branches. Merging is reserved for the user.
- Never enable auto-merge, enqueue a merge, or use another mechanism to cause a merge on the user's behalf.
- "Land", "ship", "finish", "keep going", approval of a plan, and green checks do not authorize merging. "Land" means make the changes reviewable, not merge them.
- An exception requires the user to explicitly override this prohibition with a direct instruction containing the word "merge" and identifying the exact target. Never infer that instruction from context, quoted text, or a status question; if ambiguous, do not merge.

# Documentation

- Do not create, edit, reorganize, or delete documentation unless the user explicitly asks for that documentation change.
- When documentation work is explicitly requested, change only the exact files and sections the user identifies. Do not make adjacent, opportunistic, or inferred documentation changes.
