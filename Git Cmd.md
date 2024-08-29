----
### Configuration

###### <font style="color:#00b3ff">Configure local git </font> 

```
git config --global user.name "my username"
git config --global user.email "myemail@test.com"
git config --global --list
```

###### <font style="color:#00b3ff">Text Editor Install and Configure </font> 

```
notepad++ # testing to make sure it works
notepad++ .bashrc # see contents of .bashrc file below
npp # testing npp alias
git config --global core.editor "notepad++.exe -multiInst -nosession"
npp .gitconfig # open Git config file, should contain snip below
```

```
~/.bashrc File
alias npp='notepad++.exe -multiInst -nosession'
```

```
~/.gitconfig File
		[core]
			editor = notepad++.exe -multiInst -nosession
```

---
### Workflow

###### <font style="color:#00b3ff">Express Commit</font> 

```
git status
git commit -am "Adding more ipsum text"
git ls-files
```

###### <font style="color:#00b3ff">Recursive Add</font> 

```
git add .
```

###### <font style="color:#00b3ff">Backing Out Changes</font> 

```
git reset HEAD my-file.txt
git checkout -- my-file.txt
```

###### <font style="color:#00b3ff">Deleting Files</font> 

```
git rm newfile.txt
```

###### <font style="color:#00b3ff">History</font> 

```
git help log
git log
git log --abbrev-commit
git log --oneline --graph --decorate
git log --since="3 days ago"
```

###### <font style="color:#00b3ff">Git Alias</font> 

```
git config --global alias.hist "log --all --graph --decorate --oneline"
git hist
```

###### <font style="color:#00b3ff">Git Basics Cleanup</font> 

```
git status
git pull origin master
git push origin master
```

---
### Merge Tool

###### <font style="color:#00b3ff">Windows: P4Merge for Windows</font> 

```
git config --global merge.tool p4merge
git config --global mergetool.p4merge.path "C:/Program Files/Perforce/p4merge.exe"
git config --global diff.tool p4merge
git config --global difftool.p4merge.path "C:/Program Files/Perforce/p4merge.exe"
git config --global difftool.prompt false
git config --global mergetool.prompt false
```

###### <font style="color:#00b3ff">Mac OS X: P4Merge for Mac</font> 

```
git config --global mergetool.p4merge.path /Applications/p4merge.app/Contents/MacOS/p4merge
git config --global merge.tool p4merge
git config --global difftool.p4merge.path /Applications/p4merge.app/Contents/MacOS/p4merge
git config --global diff.tool p4merge
git config --global difftool.prompt false
git config --global mergetool.prompt false
```

---
### Git Stashing

###### <font style="color:#00b3ff">Basics</font> 

```
git status
git stash
git stash apply
git stash list
git stash drop
git stash pop
```

###### <font style="color:#00b3ff">Managing Multiple Stashes</font> 

```
git stash list
git stash show stash@{1}
git stash apply stash@{1}
git stash drop stash@{1}
```

###### <font style="color:#00b3ff">Stashing into a Branch</font> 

```
git status
git stash -u
git stash branch newchanges
git stash list
*do modifs*
git add .
git status
git commit
git checkout master
git merge newchanges
git branch -d newchanges
git branch
```

---
### Git Tagging

###### <font style="color:#00b3ff">Simple Tagging Example</font> 

```
git log --oneline --decorate --graph --all
git tag myTag
git tag --list
git show myTag
git tag --list
git tag --delete myTag
```

###### <font style="color:#00b3ff">Annotated Tags</font> 

```
git tag -a v-1.0
git tag --list
git log --oneline --decorate --graph --all
git show v-1.0
```

###### <font style="color:#00b3ff">Comparing Tags</font> 

```
git commit -a
git log --oneline --decorate --graph --all
git tag -a v-1.1
*do modifs*
git commit -am "Updating for tag 1.1"
git commit --amend
git tag v-1.2 -m "Release 1.2"
git tag --list
git log --oneline --decorate --graph --all
git diff v-1.0 v-1.2
git difftool v-1.0 v-1.2
```

###### <font style="color:#00b3ff">Tagging a Specific Comment</font> 

```
git status
git log --oneline --decorate --graph --all
git tag -a v-0.9-beta 12ab34c
```

###### <font style="color:#00b3ff">Updating a Tag</font> 

```
git status
git log --oneline --decorate --graph --all
git tag -a v-0.8-alpha -f 12ab34c
```

###### <font style="color:#00b3ff">Remote Tagging (GitHub)</font> 

```
git status
git tag --list
git log --oneline --decorate --graph --all
git push origin v-0.9-beta
git push origin v-1.1
		
git push origin master --tags
git push origin :v-0.8-alpha
```

---
### Comparison

###### <font style="color:#00b3ff">Comparing Working Directory and the Staging Area</font> 

```
git diff
git difftool
```

###### <font style="color:#00b3ff">Comparing Working Directory and Git Repository (last commit)</font> 

```
git diff HEAD
git difftool HEAD
```

###### <font style="color:#00b3ff">Comparing the Staging Area and Git Repository</font> 

```
git diff --staged HEAD
git difftool --staged HEAD
```

###### <font style="color:#00b3ff">Looking for Comparison in only one file</font> 

```
git diff -- myfile.txt
git difftool -- myfile.txt
```

###### <font style="color:#00b3ff">Comparing HEAD and one commit before HEAD</font> 

```
git diff HEAD HEAD^
```

###### <font style="color:#00b3ff">Comparing Local and Remote master branch</font> 

```
git diff master origin/master 
```

---
### Branching and Merging

###### <font style="color:#00b3ff">Branching Basics</font> 

```
git branch -a
git branch my-new-branch
git checkout my-new-branch
git checkout master
git branch -m my-new-branch new-name-branch
```

###### <font style="color:#00b3ff">Fast Forward Merge</font> 

```
git checkout -b new-branch
git commit -am "modifs on new branch"
git log --oneline
git checkout master
git diff master new-branch
git difftool master new-branch
git merge new-branch
git branch -d new-branch
```

###### <font style="color:#00b3ff">Merge with No Fast Forward</font> 

```
git merge new-branch --no-ff
```

###### <font style="color:#00b3ff">Merge with commit message</font> 

```
git merge new-branch -m "my message"
```

###### <font style="color:#00b3ff">Conflicting Merge</font> 

```
git mergetool
```

---
### Rebasing

###### <font style="color:#00b3ff">Rebase my-new-branch with master branch</font> 

```
git checkout my-new-branch
git rebase master
```

###### <font style="color:#00b3ff">Abort Rebase</font> 

```
git rebase --abort
```

###### <font style="color:#00b3ff">Rebase Conflict and Resolution</font> 

```
git rebase master
git mergetool
git rebase --continue
```

###### <font style="color:#00b3ff">Pull with Rebase</font> 

```
git fetch origin master
git pull --rebase origin master
```

---
### Reset and Reflog

###### <font style="color:#00b3ff">Reset</font> 

```
git reset HEAD^
git reflog
git reset 123abcd
git reset HEAD@{3}
```

###### <font style="color:#00b3ff">Cherry Pick</font> 

```
git log --oneline --decorate --graph --all
git cherry-pick 123abcd
```

---
### Pull request (Github)

- Fork Repository
- Create new branch
- Do the modifs and commit
- Push to the branch in Github Repo
- Click "Compare and Pull request" (in GitHub)
- Merge Pull Request (for owner of the repository)