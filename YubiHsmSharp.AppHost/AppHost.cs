var builder = DistributedApplication.CreateBuilder(args);

var yubiAuthKey = builder.AddParameter("YubiHSM-AuthKeyId");
var yubiPassword = builder.AddParameter("YubiHSM-Password", secret: true);

var yubiHsm = builder.AddYubiHsm("yubihsm")
    .WithHttpEndpoint("localhost")
    .WithPassword(yubiAuthKey, yubiPassword);

builder.AddProject<Projects.YubiHsmSharp_Demo>("demo")
    .WithReference(yubiHsm);

builder.Build().Run();
