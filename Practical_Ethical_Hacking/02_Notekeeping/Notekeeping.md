# Notekeeping

## Effective Notekeeping

There is so much information required to do pentesting that it is impossible to
remember everything. Taking good notes is therefore essential.

Recommended tools:

* [Notion](www.notion.so), THS's favorite; apparently not available for Linux, stores
  data in the cloud (pro: accessible from everywhere, con: not for confidential
  data); GUI-based, lots of style elements using "/" commands, even including
  AI writing assistance, uses Markdown. (A)
* [Obsidian](www.obsidian.md); Alex Olsen's favorite, all operating systems,
  uses Markdown, disadvantage: images are added to the hierarchy. Syncs nicely
  with github and is free. (A)

Add structure to notes: chapters, headlines, etc.

**[Alex Olsen's youtube video:]** (https://www.youtube.com/watch?v=KpX7v5Ym3wg)

* [CherryTree](); comes packaged with Kali Linux (still up to date?), no
  syncing or working from different machines, easy to export to pdf and thus
  create a report, especially when starting from a template, data loss happened
  to several people. Verdict: no terrible, but not great either. (C)
* [Gitbook](www.gitbook.com); complicated & confusing ownership model, paid and
  rather expensive, easy to collaborate and create pdf's. (B)
* **[Joplin](joplinapp.org)**; open source, cloud option or stand-alone. Split
  write and preview (Markdown). Web clipper to save pages and screenshots from
  browser (Firefox, Chrome). Stand-alone version preferrable! **(S -- best!)**
* [Google Docs](docs.google.com); good all-around tool, supports Markdown,
  export to pdf, ability to add spreadsheets; disadvantages: Markdown and code
  highlighting need to be activated. (B)
* [Microsoft OneNote](); complicated to convert to report and some other
  disadvantages. (C)
* [github](www.github.com) and [Dropbox](www.dropbox.com) (B/C)
* [KeepNotes](); very outdated. (D)


## Screenshots for the Win

Recommended tools:

* [Greenshot](getgreenshot.org); only available for Windows and Mac, image
  editor to add notes, rectangle for highlights, borders & invert (clean look
  for report!), etc., obfuscate tool (O; set pixel size to 20), copy-paste
  possible with GUI notetaking apps 
* [Flameshot](flameshot.org); available for Linux, Windows and Mac.

## My Own Thoughts

* Longevity: keep it simple! Markdown seems to be a good choice, but images and
  links are tedious to integrate. Shortcut?
* Keep transformation into a report in mind! Markdown to LaTeX shortcut?
* Tools can become obsolete, and my notes are then lost or have to be migrated.
* GUIs are quick and easy to use (vs. obsolescence risk). Only one tool, and
  images can be copied and pasted, whereas vim + Markdown + screenshots is
  slow.

**Images in Markdown:**

Add images to Markdown documents using `![alt text](path/to/image.png)`. Captions
can be added using `![alt text](sample_image.png "Sample image caption")`, i.e.
adding the caption after the file path in double quotes. Use folder `./img` to
store images. The image syntax is like the link, just with a leading `!`!


