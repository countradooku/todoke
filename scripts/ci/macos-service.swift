// Invokes the "Send with todoke" service on a file, as Finder's Quick
// Action does: the running app's Services provider answers it.
// Usage: swift macos-service.swift FILE
import AppKit

let file = URL(fileURLWithPath: CommandLine.arguments[1])
let pasteboard = NSPasteboard(name: NSPasteboard.Name("org.todoke.todoke.e2e"))
pasteboard.clearContents()
guard pasteboard.writeObjects([file as NSURL]) else {
    FileHandle.standardError.write("cannot write the file to the pasteboard\n".data(using: .utf8)!)
    exit(1)
}
exit(NSPerformService("Send with todoke", pasteboard) ? 0 : 1)
