using GSMLib;
using System.Text;

Cryptography.A5 encryptor1 = new Cryptography.A5();
Cryptography.A5 encryptor2 = new Cryptography.A5();

byte[] initValue = new byte[(int)Cryptography.AuthTripletLengths.KC] {0, 1, 2, 3, 4, 5, 6, 7};

encryptor1.Initialise(initValue);
encryptor2.Initialise(initValue);

string data1 = "MY TEST STRING";
string data2 = "SECOND STRING";

byte[] encrypted1 = encryptor1.Encrypt(data1);
byte[] decrypted1 = encryptor2.Decrypt(encrypted1);
Console.WriteLine(Encoding.UTF8.GetString(decrypted1));

byte[] encrypted2 = encryptor1.Encrypt(data2);
byte[] decrypted2 = encryptor2.Decrypt(encrypted2);
Console.WriteLine(Encoding.UTF8.GetString(decrypted2));