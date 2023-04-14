using System.Security.Cryptography;
using System.Text;

namespace GSMLib
{
    public class Cryptography
    {
        public class A5
        {
            private LFSR LFSR1;
            private LFSR LFSR2;
            private LFSR LFSR3;

            public A5 ()
            {
                LFSR1 = new LFSR(19, new int[] { 13, 16, 17, 17 }, 8);
                LFSR2 = new LFSR(22, new int[] { 20, 21 }, 10);
                LFSR3 = new LFSR(23, new int[] { 7, 20, 21, 22 }, 10);
            }
            public A5(bool[] initValue)
            {
                LFSR1 = new LFSR(19, new int[] { 13, 16, 17, 17 }, 8);
                LFSR2 = new LFSR(22, new int[] { 20, 21 }, 10);
                LFSR3 = new LFSR(23, new int[] { 7, 20, 21, 22 }, 10);

                Initialise(initValue);
            }
            

            public void Initialise(byte[] initValue)
            {
                bool[] initBool = new bool[initValue.Length * 8];
                
                for (int i = 0; i < initValue.Length; i++)
                {
                    byte t = initValue[i];
                    for (int j = 0; j < 8; j++)
                    {
                        initBool[i * 8 + j] = (t % 2 == 1);
                        t >>= 1;
                    }
                }
                Initialise(initBool);
            }

            public void Initialise(bool[] initValue)
            {
                bool[] init1 = new bool[19], init2 = new bool[22], init3 = new bool[23];
                Array.Copy(initValue, 0, init1, 0, 19);
                Array.Copy(initValue, 19, init2, 0, 22);
                Array.Copy(initValue, 19 + 22, init3, 0, 23);

                LFSR1.init(init1);
                LFSR2.init(init2);
                LFSR3.init(init3);
            }

            public byte[] Encrypt(string data)
            {
                return Encrypt(Encoding.UTF8.GetBytes(data));
            }

            public byte[] Decrypt(byte[] encrypted)
            {
                return Encrypt(encrypted);
            }

            public byte[] Encrypt(byte[] data)
            {
                byte[] encrypted = new byte[data.Length];

                byte[] seq = GetSequence(data.Length);

                for (int i = 0; i < data.Length; i++) encrypted[i] = (byte) (seq[i] ^ data[i]);
                return encrypted;
            }

            private byte[] GetSequence(int length)
            {
                byte[] sequence = new byte[length];

                for (int i = 0; i < length; i++)
                {
                    byte v = 0;
                    for (int j = 0; j < 8; j++)
                    {
                        v <<= 1;

                        bool output = LFSR1.GetOutput() ^ LFSR2.GetOutput() ^ LFSR3.GetOutput();
                        bool clock = GetClockValue(new bool[] { LFSR1.GetClocker(), LFSR2.GetClocker(), LFSR3.GetClocker() });
                        LFSR1.shift(clock);
                        LFSR2.shift(clock);
                        LFSR3.shift(clock);

                        v |= output ? (byte) 0x01 : (byte)0x00;
                    }
                    sequence[i] = v;
                }
                return sequence;
            }

            private bool GetClockValue(bool[] values)
            {
                int count1 = 0, count0 = 0;

                foreach(bool value in values)
                {
                    if (value) count1++;
                    else count0++;
                }

                return count1 > count0 ? true : false;
            }


            private class LFSR
            {
                public int length;
                public int[] feedbacks;
                public bool[] cells;
                public int clocker;

                public LFSR (int l, int[] feedbacks, int clocker)
                {
                    cells = new bool[l];
                    this.length = l;
                    this.feedbacks = feedbacks;
                    this.clocker = clocker;
                }

                public void init(bool[] v)
                {
                    for (int i = 0; i < length; i++)
                    {
                        cells[i] = v[i];
                    }
                }

                public void shift (bool v)
                {
                    if (cells[clocker] == v)
                    {
                        for (int i = cells.Length - 1; i> 0; i--)
                        {
                            cells[i] = cells[i - 1];
                        }

                        bool newV = false;
                        foreach (int index in feedbacks)
                        {
                            newV = newV ^ cells[index];
                        }
                        cells[0] = newV;
                    }
                }

                public bool GetClocker()
                {
                    return cells[clocker];
                }

                public bool GetOutput()
                {
                    return cells[length - 1];
                }
            }
        }

        public static AuthTriplet GetAuthTriplet(byte[] seed, string KI)
        {
            return GetAuthTriplet(seed, Encoding.UTF8.GetBytes(KI));
        }

        public static AuthTriplet GetAuthTriplet(string KI)
        {
            return GetAuthTriplet(Encoding.UTF8.GetBytes(KI));
        }

        public static AuthTriplet GetAuthTriplet(byte[] KI)
        {
            Random rnd = new Random();
            byte[] seed = new byte[(int)AuthTripletLengths.RAND];
            rnd.NextBytes(seed);

            return GetAuthTriplet(seed, KI);
        }
        public static AuthTriplet GetAuthTriplet(byte[] seed, byte[] KI)
        {
            var data = new byte[seed.Length + KI.Length];
            seed.CopyTo(data, 0);
            KI.CopyTo(data, seed.Length);

            using SHA1 hash = SHA1.Create();

            byte[] res = hash.ComputeHash(data);

            byte[] KC = new byte[(int)AuthTripletLengths.KC];
            byte[] SRES = new byte[(int)AuthTripletLengths.SRES];

            Array.Copy(res, 0, KC, 0, (int)AuthTripletLengths.KC);
            Array.Copy(res, (int)AuthTripletLengths.KC, SRES, 0, (int)AuthTripletLengths.SRES);

            return new AuthTriplet(seed, KC, SRES);
        }

        public enum AuthTripletLengths
        {
            RAND = 64,
            KC = 8,
            SRES = 12
        }

        public class AuthTriplet
        {
            public byte[] RAND;
            public byte[] KC;
            public byte[] SRES;

            public AuthTriplet()
            {
                RAND = new byte[(int)AuthTripletLengths.RAND];
                KC = new byte[(int)AuthTripletLengths.KC];
                SRES = new byte[(int)AuthTripletLengths.SRES];
            }
            public AuthTriplet(byte[] rAND, byte[] kC, byte[] sRES)
            {
                RAND = rAND;
                KC = kC;
                SRES = sRES;
            }
        }

    }
}