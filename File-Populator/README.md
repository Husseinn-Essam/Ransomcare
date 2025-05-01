# File-Populator
Just a script that populates a target folder with dummy files. for testing purposes

### How to run
Simply ```python populate.py target_folder```

### CMDline arguments
| Arg short | Arg long | Description |
| :---: | :-----------: | :--------------------------------------------: |
|  | folderpath | Path to the target folder, it must be empty or non-existent |
| -h | --help | Help menu |
| -d | --maxdepth | Max Depth of nested folders |
| -s | --foldersize | Intended size of 1 folder in Bytes, not the overall size after finishing |
| -c | --foldercount | Folders count per each nested folder |
| -i | --samples | Path to a folder containing some sample files to copy from |

### Sample command
```py populate.py "./populated" -d 2 -s 500 -c 10 -i "./samples"```