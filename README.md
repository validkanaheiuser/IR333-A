# XoaInfo C2 Redirect Builder (GitHub Actions)

This repository contains the automated build pipeline for compiling native iOS `arm64` and `arm64e` (with Apple PAC ABI) tweak packages on GitHub Actions macOS runners.

## Structure
- `.github/workflows/build.yml`: macOS GitHub Actions workflow using Xcode & Apple Clang.
- `src/c2redirect.m`: Network interception and redirection hook implementation.
- `src/filter.plist`: MobileSubstrate/ElleKit filter plist targeting the test processes.

## How to Build on GitHub
1. Push this repository to GitHub:
   ```bash
   git init
   git add .
   git commit -m "Initial commit for iOS arm64e CI build"
   git remote add origin https://github.com/<YOUR_USER>/<REPO_NAME>.git
   git push -u origin main
   ```
2. Go to **Actions** tab on your GitHub repository.
3. Once the workflow completes, download the generated `.deb` package from the **Artifacts** section.
