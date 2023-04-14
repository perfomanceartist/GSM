using GSMLib;

Client client = new Client();

client.Connect();

Console.WriteLine("Authentication. Enter password:");
string? password = Console.ReadLine();
if (password == null) return;

bool authResult = client.Authenticate(password);
if (!authResult)
{
    Console.WriteLine("Authentication was not successful");
    return;
}
Console.WriteLine("Authentication successful");
while (true)
{
    Console.WriteLine("Enter data to send:");
    string? data = Console.ReadLine();
    if (data == null) continue;
    client.SendData(data);
    string received;
    bool res = client.ReceiveData(out received);
    if (!res)
    {
        Console.WriteLine("Got an error!");
        break;
    }
    Console.WriteLine("Received Data: " + received); 
}

