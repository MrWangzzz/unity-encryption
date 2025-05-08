using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;

public class MyCustomBuildProcessor : IPostprocessBuildWithReport
{
    private string globalPath = "/Data/Managed/Metadata/global-metadata.dat";
    int IOrderedCallback.callbackOrder { get { return 0; } }

    public void OnPostprocessBuild(BuildReport report)
    {
        throw new System.NotImplementedException();
    }

    void IPostprocessBuildWithReport.OnPostprocessBuild(BuildReport report)
    {
        var path = report.summary.outputPath + globalPath;

        byte[] olddata = File.ReadAllBytes(path);


        int size = olddata.Length;
        var newdata= EncryptFile(olddata,ref size);

        File.WriteAllBytes(path, newdata);
        Debug.Log("���ܳɹ�"!);
    }


    private static RandomNumberGenerator rng = RandomNumberGenerator.Create();

    public static byte[] EncryptFile(byte[] src, ref int fileSize)
    {
        // ���������Կ���ȣ�130-140��
        int kl = GetRandomInt(130, 140);
        uint[] p_passwordArr = new uint[kl];

        // ������Կ
        for (int i = 0; i < kl; i++)
        {
            p_passwordArr[i] = GetRandomUInt();
        }

        // ��ȫ����С
        const int safe_size = 1024;
        // ��������С
        int encrypt_size = fileSize - safe_size;
        // ���������ܴ�С
        int klsize = (kl + 1) * sizeof(uint);
        // �����µ��ֽ����飬�������� + Դ�ļ�
        byte[] des = new byte[fileSize + klsize];

        // ���ư�ȫ��
        Array.Copy(src, 0, des, 0, safe_size);

        // ������ָ��
        int dataStart = safe_size;
        byte[] keyBytes = new byte[kl * sizeof(uint)];
        Buffer.BlockCopy(p_passwordArr, 0, keyBytes, 0, keyBytes.Length);

        // ��д�������Կ����
        uint header = (GetRandomUInt() & 0xFFFF0000) | ((uint)kl & 0xFFFF);
        Buffer.BlockCopy(BitConverter.GetBytes(header), 0, des, dataStart, sizeof(uint));

        // д����Կ
        dataStart += sizeof(uint);
        Buffer.BlockCopy(keyBytes, 0, des, dataStart, keyBytes.Length);
        dataStart += keyBytes.Length;

        // XOR ��������
        for (int i = 0; i < encrypt_size; i += 4)
        {
            int index = (i + (i / kl)) % kl;
            uint encryptedValue = p_passwordArr[index] ^ BitConverter.ToUInt32(src, safe_size + i);
            Buffer.BlockCopy(BitConverter.GetBytes(encryptedValue), 0, des, dataStart + i, sizeof(uint));
        }

        fileSize += klsize;
        return des;
    }

    // ���� 32 λ�������
    private static uint GetRandomUInt()
    {
        byte[] randomBytes = new byte[4];
        rng.GetBytes(randomBytes);
        return BitConverter.ToUInt32(randomBytes, 0);
    }

    // ����ָ����Χ�ڵ��������
    private static int GetRandomInt(int min, int max)
    {
        byte[] randomBytes = new byte[4];
        rng.GetBytes(randomBytes);
        int value = BitConverter.ToInt32(randomBytes, 0);
        return Math.Abs(value % (max - min + 1)) + min;
    }

}

