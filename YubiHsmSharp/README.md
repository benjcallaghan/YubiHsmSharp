# YubiHsmSharp

This library is a C# wrapper around [libyubihsm](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-tools-libyubihsm.html), a C library for communicating with a YubiHSM 2. The [YubiHSM SDK](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-index-tools.html) is not included in this project and must be installed separately.

## Usage

Debug output is controlled with the property `YubiConnector.Verbosity`, which can be set before the library is initialized.

First step of using a YubiHSM 2 is to initialize the library with `new YubiModule()`, initialize a connector with `YubiModule.InitializeConnector()`, and then connect it to the YubiHSM 2 with `YubiConnector.Connect()`. After this, a session must be established with `YubiConnector.CreateSession()`.

When a session is established, commands can be exchanged over it. Raw commands can be sent with `YubiSession.SendMessage()`. However, nearly all commands are exposed as methods on `YubiModule`, `YubiConnector`, or `YubiSession`.

## Example

Here is a small example of establishing a session with a YubiHSM 2 and fetching some pseudo random bytes before closing the session.

```csharp
public static void Main()
{
    using YubiModule module = YubiModule.Instance;
    using YubiConnector connector = module.InitializeConnector("http://localhost:12345"u8);
    connector.Connect();
    using YubiSession session = connector.CreateSession(1, "password"u8);
    
    byte[] data = new byte[128];
    int dataLength = session.GetPseudoRandom(data);
    Debug.Assert(dataLength == data.Length);

    // session, connector, and module are automatically closed at the end of the scope.
}
```

## Disclaimer

I do not own a YubiHSM 2 device, so this project is largely theoretical. Anyone wishing to use this library is strongly encouraged to perform their own testing against a YubiHSM 2 device.
