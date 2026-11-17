// Package genadb is the public Go SDK of Setu (Setu-SDK): an encrypted bridge
// between your IDE and any Android device, anywhere. It connects a local adb
// client (Android Studio, any IDE, plain adb) to a physical Android device on
// another network, as if the device were plugged into this machine.
//
// The central type is [SetuClient], a session manager built with functional
// options; each connection is a [SetuSession]:
//
//	c, err := genadb.New(
//		genadb.WithRelayURL("wss://relay.example.com/"),
//		genadb.WithStateDir("~/.setu"),
//	)
//	sess, err := c.Connect(ctx, genadb.ConnectRequest{PairingCode: "1234-ABCDEF"})
//	fmt.Println("adb connect", sess.ADBAddr())
//
// Client and Session, the names used before v1.0.1, remain as aliases of
// SetuClient and SetuSession, and the import path is unchanged, so existing
// code compiles as is.
//
// Collaborators are expressed as small interfaces ([TransportProvider],
// [AuthProvider], [AuditSink], [DeviceDiscoverer]) so they can be replaced in
// tests or by embedding applications. Wire protocol, framing and the
// cryptographic state machines are deliberately not part of this package.
package genadb
