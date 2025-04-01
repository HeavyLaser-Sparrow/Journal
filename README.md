# Encrypted Journal

An encrypted journal application built using Python, Tkinter, SQLite, and Fernet encryption. This application allows users to store and manage journal entries securely, with encryption applied to the journal content.

## Features

- **Secure Storage**: Entries are encrypted using Fernet encryption before being saved to the database.
- **Security**: Please remember to hide the key2.key file after first running of script, and then manually put it back when want to use it
- **User-friendly Interface**: Built using Tkinter for easy interaction.
- **Markdown Support**: Entries can be written using Markdown formatting.
- **Tagging System**: Users can tag journal entries for better organization.
- **Entry Management**: Save, delete, and view entries with a simple interface.
- **Keyboard Shortcuts**:
  - `Ctrl + s` → Save entry
  - `Ctrl + d` → Delete selected entry

## Installation

### Prerequisites

Ensure you have Python installed (version 3.6 or later recommended).

### Required Libraries

Install the necessary dependencies by running:

```sh
pip install cryptography markdown
```

### From the Binary

You can install the elf binary, and run ./journal in the directory you want your journal to be in.

### Usage

If you want to "lock" your journal, you can just move the key2.key file one step up out of the journal directory,
and then move it back in when you want to use it.
The code will break if it runs without the key2.key file (makes another key2.key file in the journal directory), but you can fix it by just deleting the new key2.key file in the journal directory and moving in the original key2.key file.

### Future Features

I have plans to fix the creation of a new key2.key file if the original key2.key file is missing, but I am not sure if the
key2.key file appearing even if you have one is a feature or a bug.
