We have the CI on GitHub Actions failing with

```
Run actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
Syncing repository: streamingfast/reth
Getting Git version info
Temporarily overriding HOME='/home/runner/work/_temp/4a6667a3-8714-458a-b576-3599f0dabf57' before making global git config changes
Adding repository directory to the temporary git global config as a safe directory
/usr/bin/git config --global --add safe.directory /home/runner/work/reth/reth
Deleting the contents of '/home/runner/work/reth/reth'
Initializing the repository
Disabling automatic garbage collection
Setting up auth
Fetching the repository
Determining the checkout info
/usr/bin/git sparse-checkout disable
/usr/bin/git config --local --unset-all extensions.worktreeConfig
Checking out the ref
/usr/bin/git log -1 --format=%H
88fe789108041ad28f79bb1293e5b77999a76907
Removing auth
  Removing SSH command configuration
  /usr/bin/git config --local --name-only --get-regexp core\.sshCommand
  /usr/bin/git submodule foreach --recursive sh -c "git config --local --name-only --get-regexp 'core\.sshCommand' && git config --local --unset-all 'core.sshCommand' || :"
  Error: fatal: No url found for submodule path '.worktrees/feature-update-to-reth-2.x' in .gitmodules
  Error: The process '/usr/bin/git' failed with exit code 128
```

Investigate what's wrong maybe with how our definitions are set in `.github` folder.
