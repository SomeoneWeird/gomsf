package gomsf_test

import (
	. "github.com/SomeoneWeird/gomsf"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"strings"
)

var _ = Describe("Gomsf", func() {

	r := RPC{Host: "127.0.0.1", Port: 55553}

	Describe("Authentication", func() {

		Context("login", func() {

			It("should fail", func() {

				loginInfo := r.AuthLogin("wronguser", "wrongpass")

				Expect(loginInfo.Error).To(Equal(true))
				Expect(loginInfo.Error_message).To(Equal("Login Failed"))

			})

			It("should succeed", func() {

				loginInfo := r.AuthLogin("user", "pass")

				Expect(loginInfo.Error).To(Equal(false))
				Expect(strings.HasPrefix(loginInfo.Token, "TEMP")).To(Equal(true))

				r.Token = loginInfo.Token

			})

		})

		Context("tokens", func() {

			XIt("should generate a new token", func() {})
			XIt("should add a valid token", func() {})
			XIt("should list all tokens, including our inserted one", func() {})
			XIt("should remove our inserted token", func() {})

		})

	})

	Describe("Core", func() {

		Context("Modules", func() {

			XIt("should add a module to the search path", func() {})
			XIt("should list all available modules", func() {})
			XIt("should reload all modules", func() {})

		})

		Context("Settings", func() {

			XIt("should save current config", func() {})
			XIt("should set global variable", func() {})
			XIt("should unset global variable", func() {})

		})

		Context("Threads", func() {

			XIt("should list current threads", func() {})
			XIt("should kill a thread", func() {})

		})

		XIt("should display versioning information", func() {})
		// XIt("should stop the rpc server", func() {})

	})

	Describe("Console", func() {

		Context("Management", func() {

			XIt("should create a new console", func() {})

			XIt("should list all consoles including our new one", func() {})

			XIt("should write data into our new console", func() {})
			XIt("should read data from our new console", func() {})

			XIt("should autocomplete properly", func() {})

			XIt("should detach from our console", func() {})
			XIt("should destroy our console", func() {})
			XIt("should list all consoles not including our new one", func() {})

		})

		Context("Session", func() {

			XIt("should detach from our session", func() {})
			XIt("should kill our session", func() {})

		})

	})

	Describe("Jobs", func() {

		XIt("should list all running jobs", func() {})
		XIt("should list info on a running job", func() {})
		XIt("should stop a running job", func() {})

	})

	Describe("Modules", func() {

		XIt("should list all available exploits", func() {})
		XIt("should list all available auxiliary modules", func() {})
		XIt("should list all available post modules", func() {})
		XIt("should list all available payloads", func() {})
		XIt("should list all available encoders", func() {})
		XIt("should list all available nop modules", func() {})

		XIt("should list information about a specific module", func() {})
		XIt("should list available options for a specific module", func() {})
		XIt("should list payloads compatible with the specific exploit", func() {})
		XIt("should list payloads compatible with an exploit AND a specific target", func() {})
		XIt("should return sessions that are compatible with specified module", func() {})
		XIt("should return an encoded payload", func() {})
		XIt("should start a module", func() {})

	})

	Describe("Plugins", func() {

		XIt("should load a plugin", func() {})
		XIt("should unload a plugin", func() {})
		XIt("should return all loaded plugins", func() {})

	})

	Describe("Session", func() {

		XIt("should list all running sessions", func() {})
		XIt("should stop a running session", func() {})

		Context("Shell", func() {

			XIt("should read data from a shell session", func() {})
			XIt("should write data into a shell session", func() {})

		})

		Context("Meterpreter", func() {

			XIt("should write data into a meterpreter session", func() {})
			XIt("should read data from a meterpreter session", func() {})
			XIt("should run a command in a meterpreter session", func() {})
			XIt("should execute a script in a meterpreter session", func() {})
			XIt("should detach from a meterpreter session", func() {})
			XIt("should kill a meterpreter session", func() {})
			XIt("should test autocomplete", func() {})

		})

		XIt("should list modules compatible with specified session", func() {})
		XIt("should upgrade a shell session to a meterpreter shell", func() {})

		Context("Ring", func() {

			XIt("should clear ring buffer for session", func() {})
			XIt("should get last pointer for session", func() {})
			XIt("should write data into session", func() {})
			XIt("should read data from a session", func() {})

		})

	})

})
