var builder = DistributedApplication.CreateBuilder(args);

var authKeyId = builder.AddParameter("YubiHsm-AuthKeyId");
var password = builder.AddParameter("YubiHsm-Password");

var yubihsm = builder.AddYubiHsm("yubihsm", "http://localhost:12345")
    .WithPassword(authKeyId, password);

builder.AddProject<Projects.YubiHsmSharp_Demo>("demo")
    .WithReference(yubihsm);

builder.Build().Run();
