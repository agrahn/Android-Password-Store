# Release Procedure

## Phase 1: Release Preparation
### On GitHub
* **Create Milestone**: Create a new milestone named `v1.16.4`
* **Close Milestone**: Close the current milestone

### Locally
* **Update Local Repo**: Run `git pull`
* **Switch Branch**: Run `git switch release-prep`
* **Changelogs**: Add F-Droid changelogs and descriptions
* **Version Bump**: Manually fix `app/version.properties`
* **Stage Changes**: Run `git add .`
* **Commit**: Run `git commit -S`
* **Push**: Run `git push`

### On GitHub
* **Merge**: Squash and merge `release-prep` into `release-1.16`

---

## Phase 2: Tagging and GitHub Deployment
### Locally
* **Update Local Repo**: Run `git pull`
* **Switch Branch**: Run `git switch release-1.16`
* **Create Tag**: Run `git tag -a v1.16.4 -m "version 1.16.4"`
* **Push Tag**: Run `git push origin v1.16.4`
  * *Note: This triggers the `deploy_github_release.yml` action to create a draft release.*

---

## Phase 3: F-Droid Submission
### On GitLab
* **Fork**: Update your `fdroiddata` fork

### Locally (in `fdroiddata` repository)
* **Switch to Master**: Run `git checkout master`
* **Update Repo**: Run `git pull`
* **Create Branch**: Run `git checkout -b app.passwordstore.agrahn`
* **Update Metadata**: Manually update `metadata/app.passwordstore.agrahn.yml`
* **Stage Changes**: Run `git add .`
* **Commit**: Run `git commit -m "update app.passwordstore.agrahn to v1.16.4"`
* **Push**: Run `git push`

### On GitLab
* **Merge Request**: Create a merge request and select the update template

---

## Phase 4: Finalising the Release
### On GitHub (After F-Droid MR checks pass)
* **Publish**: Update the release notes and publish the draft release

### Locally
* **Switch Branch**: Run `git checkout release-1.16`
* **Update Repo**: Run `git pull`
* **Switch to Develop**: Run `git checkout develop`
* **Merge Release**: Run `git merge release-1.16`
* **Push Develop**: Run `git push`
* **Snapshot Bump**: Run `./gradlew bumpSnapshot`
* **Stage Snapshot**: Run `git add .`
* **Commit Snapshot**: Run `git commit -S -m "bump snapshot"`
* **Push Snapshot**: Run `git push`
