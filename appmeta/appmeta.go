// Package appmeta holds static application metadata for XSSHuntS.
package appmeta

import "strings"

const (
	Version     = "1.1.0"
	App         = "XSSHuntS"
	Description = "An Automatic XSS Scanner"
	Author      = "zapstiko"
	GitHub      = "https://github.com/zapstiko/xsshunts"
)

// Banner is the tool's terminal banner (graffiti-style ASCII art of the name).
const Banner = `
                      .__                  __
___  ___  ______ _____|  |__  __ __  _____/  |_  ______
\  \/  / /  ___//  ___/  |  \|  |  \/    \   __\/  ___/
 >    <  \___ \ \___ \|   Y  \  |  /   |  \  |  \___ \
/__/\_ \/____  >____  >___|  /____/|___|  /__| /____  >
      \/     \/     \/     \/           \/          \/  v` + Version + `

`

// BannerLines returns the banner split into lines.
func BannerLines() []string {
	return strings.Split(strings.Trim(Banner, "\n"), "\n")
}
