// Package genadb is the public Go SDK for New-GenADB: it connects a local adb
// client (Android Studio, any IDE, plain adb) to a physical Android device on
// another network, as if the device were plugged into this machine.
//
// The central type is [Client], a session manager built with functional
// options:
//
//	c, err := genadb.New(
//		genadb.WithRelayURL("wss://relay.example.com/"),
//		genadb.WithStateDir("~/.genadb"),
//	)
//	sess, err := c.Connect(ctx, genadb.ConnectRequest{PairingCode: "1234-ABCDEF"})
//	fmt.Println("adb connect", sess.ADBAddr())
//
// Collaborators are expressed as small interfaces ([TransportProvider],
// [AuthProvider], [AuditSink], [DeviceDiscoverer]) so they can be replaced in
// tests or by embedding applications. Wire protocol, framing and the
// cryptographic state machines are deliberately not part of this package.
package genadb
