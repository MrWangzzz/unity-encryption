#include "il2cpp-config.h"
#include "MetadataLoader.h"
#include "os/File.h"
#include "os/Mutex.h"
#include "utils/MemoryMappedFile.h"
#include "utils/PathUtils.h"
#include "utils/Runtime.h"
#include "utils/Logging.h"


#if IL2CPP_TARGET_ANDROID && IL2CPP_TINY_DEBUGGER && !IL2CPP_TINY_FROM_IL2CPP_BUILDER
#include <stdlib.h>
extern "C"
{
    void* loadAsset(const char* path, int *size, void* (*alloc)(size_t));
}
#elif IL2CPP_TARGET_JAVASCRIPT && IL2CPP_TINY_DEBUGGER && !IL2CPP_TINY_FROM_IL2CPP_BUILDER
extern void* g_MetadataForWebTinyDebugger;
#endif


void* PromiseAntiencryption(void* src, int64_t len)
{

    char* cp_src = (char*)src; // ���ֽ�����ʽ�����ļ��ڴ�buffer
    const int safe_size = 1024; // ��ȫ����С
    // ���������ĸ��ֽڵ�ʮ��λΪ�����������鳤��
    unsigned int* ip_mask = (unsigned int*)(cp_src + safe_size);
    // ��ȡ�������������鳤��
    int kl = (int)((*ip_mask) & 0xffff);
    // ��ȡ���ܴ��볤��
    const int64_t code_segment_size = len - sizeof(uint32_t) * (kl + 1);
    const int64_t code_encryption_size = code_segment_size - safe_size;
    // ������ʵ������ڴ�ӳ�䳤�Ȳ�����һ���µ��ڴ��
    char* buffer = (char*)malloc(code_segment_size);
    // ����ȫ������Copy���µ��ڴ����
    memcpy(buffer, cp_src, safe_size);
    // ��ȡ��������ַָ��
    unsigned int* ip_data = (unsigned int*)(buffer + safe_size);
    unsigned int* t = ip_mask + 1;//��������ָ��
    unsigned int* d = ip_mask + kl + 1;//��������ַָ��
    // �����ܴ���
    for (int64_t i = 0; i < code_encryption_size; i += 4)
    {
        *(ip_data + i / 4) = (*(t + ((i + (i / kl)) % kl))) ^ (*(d + i / 4));
    }
    return (void*)buffer;
}

extern void *g_cacheFileHeader = NULL;
extern void *g_cacheDecodeHeader = NULL;
void* il2cpp::vm::MetadataLoader::LoadMetadataFile(const char* fileName)
{
#if IL2CPP_TARGET_ANDROID && IL2CPP_TINY_DEBUGGER && !IL2CPP_TINY_FROM_IL2CPP_BUILDER
    std::string resourcesDirectory = utils::PathUtils::Combine(utils::StringView<char>("Data"), utils::StringView<char>("Metadata"));

    std::string resourceFilePath = utils::PathUtils::Combine(resourcesDirectory, utils::StringView<char>(fileName, strlen(fileName)));

    int size = 0;
    return loadAsset(resourceFilePath.c_str(), &size, malloc);
#elif IL2CPP_TARGET_JAVASCRIPT && IL2CPP_TINY_DEBUGGER && !IL2CPP_TINY_FROM_IL2CPP_BUILDER
    return g_MetadataForWebTinyDebugger;
#else
    std::string resourcesDirectory = utils::PathUtils::Combine(utils::Runtime::GetDataDir(), utils::StringView<char>("Metadata"));

    std::string resourceFilePath = utils::PathUtils::Combine(resourcesDirectory, utils::StringView<char>(fileName, strlen(fileName)));

    int error = 0;
    os::FileHandle* handle = os::File::Open(resourceFilePath, kFileModeOpen, kFileAccessRead, kFileShareRead, kFileOptionsNone, &error);
    if (error != 0)
    {
        utils::Logging::Write("ERROR: Could not open %s", resourceFilePath.c_str());
        return NULL;
    }

    void *fileBuffer = g_cacheFileHeader = utils::MemoryMappedFile::Map(handle);

    int ero;
    int64_t length = os::File::GetLength(handle, &ero);
    void* decBuffer = g_cacheDecodeHeader = PromiseAntiencryption(fileBuffer, length);

    os::File::Close(handle, &error);
    if (error != 0)
    {
        utils::MemoryMappedFile::Unmap(fileBuffer);
        fileBuffer = NULL;
        return NULL;
    }

    return decBuffer;
#endif
}



void il2cpp::vm::MetadataLoader::UnloadMetadataFile(void* fileBuffer)
{
    if (g_cacheDecodeHeader == fileBuffer)
    {
        free(fileBuffer);
        fileBuffer = g_cacheFileHeader;
    }

#if IL2CPP_TARGET_ANDROID && IL2CPP_TINY_DEBUGGER && !IL2CPP_DEBUGGER_TESTS
    free(fileBuffer);
#else
    bool success = il2cpp::utils::MemoryMappedFile::Unmap(fileBuffer);
    NO_UNUSED_WARNING(success);
    IL2CPP_ASSERT(success);
#endif
}
