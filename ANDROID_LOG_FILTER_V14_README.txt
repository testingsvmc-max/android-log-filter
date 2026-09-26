ANDROID LOG FILTER V14 - WINDOWS
================================

Run:
  Put the .py and .bat files in the same folder, then double-click
  Extract the complete ZIP, then double-click run_android_log_filter_v14.bat.
  Do not move only the Python file: keep the bundled tkinterdnd2 folder beside
  it. You may also run android_log_filter_timestamp_v14.py directly from that folder.

Timestamp filtering:
  - Enter only From or only To to match that exact timestamp.
  - 12:08 matches every log line during minute 12:08.
  - 12:08:03 matches every log line during second 12:08:03.
  - 12:08:03.329 matches millisecond 12:08:03.329.
  - Enter both From and To to filter a time range as before.
  - Date-time values such as 09-14 12:08:03.329 are also supported.

Safe drag and drop:
  - The old native ctypes/WndProc drag hook was removed because it caused the
    fatal "Python error: Aborted" shown in the crash log on Python 3.14.
  - Drag/drop uses tkinterdnd2 0.6.3 through Tk's supported event system.
  - The Windows x64 Tcl/Tk 8 and Tcl/Tk 9 runtimes are bundled for offline use.
  - No pip installation and no internet connection are required.
  - If the bundled folder is removed, the app explains the problem visibly;
    Open Log File still works.

Crash diagnostics:
  - .log.01 and other numbered/rotated text logs are supported.
  - Application, drag/drop, file-reading, rendering, Tkinter callback, thread,
    and fatal Python errors are written to:
      %LOCALAPPDATA%\AndroidLogFilter\android_log_filter_crash.log
  - If LOCALAPPDATA is unavailable, the log is stored under the Windows temp
    directory in AndroidLogFilter\android_log_filter_crash.log.
  - Files over 100 MB are not loaded to prevent Tkinter from exhausting memory;
    the app displays a warning and remains open.

Navigate and copy:
  - Click a line in Filtered Result to show and highlight its original line in
    the upper Source Log pane.
  - Drag to select any text in either pane, then press Ctrl+C.
  - Right-click for Copy, Copy Line, and Select All.
  - Use Ctrl+Click on a line to mark/unmark it with the selected mark color.

Open logs:
  - Click Open Log File, or drag files directly into Source Log.
  - File names are not restricted by extension.
  - Supported examples: .log, .txt, .log.1, .log.14, .txt.3, .out,
    .trace, .dump, and files without an extension.
  - UTF-8 and UTF-16 text logs are supported.
  - Binary and missing files are ignored safely instead of crashing.

The existing Boolean search, section show/hide, time filtering, category
filtering, highlighting, manual line marks, export, and ADB features remain.
