using System;

namespace DSA
{
    class Test
    {
        [STAThreadAttribute]
        static void Main(string[] args)
        {
            Program program = new Program();
            program.ShowDialog();
        }
    }
}
