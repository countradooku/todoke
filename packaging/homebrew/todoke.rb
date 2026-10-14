# Template: replace @VERSION@ and @SHA256@ (the universal zip's) before
# submitting to a tap. Paths in zap: todoke-daemon's paths.rs (macOS).
cask "todoke" do
  version "@VERSION@"
  sha256 "@SHA256@"

  url "https://github.com/countradooku/todoke/releases/download/v#{version}/todoke-#{version}-macos-universal.zip"
  name "todoke"
  desc "End-to-end encrypted file transfer between your devices"
  homepage "https://github.com/countradooku/todoke"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: ">= :ventura"

  app "todoke.app"
  binary "#{appdir}/todoke.app/Contents/MacOS/todoke"

  uninstall quit:      "org.todoke.todoke",
            launchctl: "org.todoke.todoke.agent"

  # The keychain item (service org.todoke.todoke) stays: zap cannot reach it.
  zap trash: [
    "~/Library/Application Support/org.todoke.todoke",
    "~/Library/Caches/org.todoke.todoke",
    "~/Library/HTTPStorages/org.todoke.todoke",
    "~/Library/Preferences/org.todoke.todoke.plist",
    "~/Library/Saved Application State/org.todoke.todoke.savedState",
  ]
end
