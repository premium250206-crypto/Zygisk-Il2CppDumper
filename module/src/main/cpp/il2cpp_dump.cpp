//
// Created by Perfare on 2020/7/4.
//

#include "il2cpp_dump.h"
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cinttypes> // 32/64비트 호환용 헤더 (PRIu64 매크로)
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h> // mkdir 추가
#include "xdl.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"

// 함수 프로토타입 선언
void init_il2cpp_api(void *handle);

#define DO_API(r, n, p) r (*n) p

#include "il2cpp-api-functions.h"

#undef DO_API

static uint64_t il2cpp_base = 0;
static uint64_t il2cpp_size = 0; // 덤프할 라이브러리 크기 저장을 위한 전역 변수

// ==============================================================================
// === 헬퍼 함수 (메모리 덤프) ===
// ==============================================================================
void dump_memory_region(uint64_t start_addr, size_t size, const char *out_path) {
    if (size == 0 || start_addr == 0) {
        LOGE("주소(0x%" PRIx64 ") 또는 크기(%zu)가 유효하지 않아 메모리 덤프에 실패했습니다.", start_addr, size);
        return;
    }
    LOGI("메모리 덤프 시도: Start=0x%" PRIx64 ", Size=%zu bytes", start_addr, size);

    FILE *out_file = fopen(out_path, "wb");
    if (!out_file) {
        LOGE("출력 파일을 열 수 없습니다: %s", out_path);
        return;
    }

    fwrite((void *) start_addr, 1, size, out_file);
    fclose(out_file);
    LOGI("메모리 덤프 완료: %s", out_path);
}

// ==============================================================================
// === [수정됨] 헬퍼 함수 (메타데이터 메모리 스캔) ===
// ==============================================================================

// global-metadata.dat 헤더 구조 (v24+)
struct Il2CppGlobalMetadataHeader {
    uint32_t magicNumber; // 0xFAB11BAF
    uint32_t version;
    uint32_t fileSize;
    // ... 이하 생략
};

// 메타데이터 Magic Number
const uint32_t METADATA_MAGIC = 0xFAB11BAF;

void dump_metadata_from_memory(const char *out_path) {
    LOGI("Scanning memory for global-metadata.dat header (0x%X)...", METADATA_MAGIC);
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        LOGE("Failed to open /proc/self/maps");
        return;
    }

    char line[1024];
    uint64_t start, end;
    char perms[5];
    while (fgets(line, sizeof(line), maps)) {
        // 읽기 가능('r')하고 공유되지 않은('p') 메모리 영역을 찾습니다.
        if (sscanf(line, "%" PRIx64 "-%" PRIx64 " %4s", &start, &end, perms) != 3) continue;
        
        // 'r' (읽기) 권한이 있어야 함
        if (perms[0] != 'r') continue;

        // 너무 작은 영역은 건너뜀
        if (end - start < sizeof(Il2CppGlobalMetadataHeader)) continue;

        char *ptr = (char *)start;
        char *end_ptr = (char *)end;
        
        // 4바이트 정렬된 주소부터 스캔 시작
        ptr = (char*)(((uintptr_t)ptr + 3) & ~3); 

        while (ptr <= (end_ptr - sizeof(Il2CppGlobalMetadataHeader))) {
            if (*(uint32_t *)ptr == METADATA_MAGIC) {
                // Magic Number 일치!
                Il2CppGlobalMetadataHeader *header = (Il2CppGlobalMetadataHeader *)ptr;

                // 버전 및 파일 크기 유효성 검사 (비정상적인 값 필터링)
                if (header->version >= 20 && header->version <= 30) { // e.g., Unity 2017-2023
                    if (header->fileSize > 0 && header->fileSize < 100 * 1024 * 1024) { // 100MB 이하
                        
                        // 파일 전체가 이 메모리 영역 안에 있는지 확인
                        if ((uint64_t)ptr + header->fileSize > end) {
                            LOGW("Metadata header at %p, but file size (%u) exceeds memory region (ends at %p). Skipping.", ptr, header->fileSize, (void*)end);
                            ptr += 4;
                            continue;
                        }

                        LOGI("Found metadata header in memory at %p!", ptr);
                        LOGI("Version: %d, FileSize: %u bytes", header->version, header->fileSize);
                        
                        // 메모리에서 파일 덤프
                        dump_memory_region((uint64_t)ptr, header->fileSize, out_path);
                        fclose(maps);
                        return;
                    }
                }
            }
            ptr += 4; // 다음 4바이트로 이동
        }
    }

    fclose(maps);
    LOGE("global-metadata.dat header (0x%X) not found in memory.", METADATA_MAGIC);
}

// ==============================================================================
// === il2cpp_api_init 함수 (선언부) ===
// ==============================================================================
void il2cpp_api_init(void *handle) {
    LOGI("il2cpp_handle: %p", handle);
    init_il2cpp_api(handle); // 실제 정의는 파일 하단에 있습니다.
    if (il2cpp_domain_get_assemblies) {
        Dl_info dlInfo;
        if (dladdr((void *) il2cpp_domain_get_assemblies, &dlInfo)) {
            il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
            LOGI("il2cpp_base: %" PRIx64"", il2cpp_base);

            // /proc/self/maps를 파싱하여 라이브러리 크기 찾기
            FILE *maps = fopen("/proc/self/maps", "r");
            if (maps) {
                char line[1024];
                uint64_t start = 0, end = 0;
                uint64_t lib_end = 0;
                while (fgets(line, sizeof(line), maps)) {
                    if (strstr(line, dlInfo.dli_fname)) { 
                        if (sscanf(line, "%" PRIx64 "-%" PRIx64, &start, &end) == 2) {
                            if (start == il2cpp_base) { 
                                lib_end = end;
                                // 연속된 메모리 블록의 끝까지 읽기
                                while (fgets(line, sizeof(line), maps)) {
                                    if (strstr(line, dlInfo.dli_fname)) {
                                        if (sscanf(line, "%" PRIx64 "-%" PRIx64, &start, &end) == 2) {
                                            lib_end = end; 
                                        }
                                    } else {
                                        break; 
                                    }
                                }
                                il2cpp_size = lib_end - il2cpp_base;
                                // 32/64비트 호환성을 위해 PRIu64 매크로 사용
                                LOGI("libil2cpp.so memory region found: Size=%" PRIu64 " bytes", il2cpp_size);
                                break;
                            }
                        }
                    }
                }
                fclose(maps);
            } else {
                LOGW("/proc/self/maps file open failed, could not find library size.");
            }
        } else {
            LOGE("dladdr failed for il2cpp_domain_get_assemblies");
        }
    } else {
        LOGE("Failed to initialize il2cpp api.");
        return;
    }
    while (!il2cpp_is_vm_thread(nullptr)) {
        LOGI("Waiting for il2cpp_init...");
        sleep(1);
    }
    auto domain = il2cpp_domain_get();
    il2cpp_thread_attach(domain);
}

// ... (dump_method, dump_property, dump_field, dump_type 함수들은 변경 없음) ...
// ... (코드가 길어서 생략합니다. 이전 답변의 함수들을 그대로 사용하시면 됩니다.) ...

std::string get_method_modifier(uint32_t flags) {
    std::stringstream outPut;
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access) {
        case METHOD_ATTRIBUTE_PRIVATE:
            outPut << "private ";
            break;
        case METHOD_ATTRIBUTE_PUBLIC:
            outPut << "public ";
            break;
        case METHOD_ATTRIBUTE_FAMILY:
            outPut << "protected ";
            break;
        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
            outPut << "internal ";
            break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC) {
        outPut << "static ";
    }
    if (flags & METHOD_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_FINAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "sealed override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT) {
            outPut << "virtual ";
        } else {
            outPut << "override ";
        }
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) {
        outPut << "extern ";
    }
    return outPut.str();
}

bool _il2cpp_type_is_byref(const Il2CppType *type) {
    auto byref = type->byref;
    if (il2cpp_type_is_byref) {
        byref = il2cpp_type_is_byref(type);
    }
    return byref;
}

std::string dump_method(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Methods\n";
    void *iter = nullptr;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        //TODO attribute
        if (method->methodPointer) {
            outPut << "\t// RVA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer - il2cpp_base;
            outPut << " VA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer;
        } else {
            outPut << "\t// RVA: 0x VA: 0x0";
        }
        outPut << "\n\t";
        uint32_t iflags = 0;
        auto flags = il2cpp_method_get_flags(method, &iflags);
        outPut << get_method_modifier(flags);
        auto return_type = il2cpp_method_get_return_type(method);
        if (_il2cpp_type_is_byref(return_type)) {
            outPut << "ref ";
        }
        auto return_class = il2cpp_class_from_type(return_type);
        outPut << il2cpp_class_get_name(return_class) << " " << il2cpp_method_get_name(method)
               << "(";
        auto param_count = il2cpp_method_get_param_count(method);
        for (int i = 0; i < param_count; ++i) {
            auto param = il2cpp_method_get_param(method, i);
            auto attrs = param->attrs;
            if (_il2cpp_type_is_byref(param)) {
                if (attrs & PARAM_ATTRIBUTE_OUT && !(attrs & PARAM_ATTRIBUTE_IN)) {
                    outPut << "out ";
                } else if (attrs & PARAM_ATTRIBUTE_IN && !(attrs & PARAM_ATTRIBUTE_OUT)) {
                    outPut << "in ";
                } else {
                    outPut << "ref ";
                }
            } else {
                if (attrs & PARAM_ATTRIBUTE_IN) {
                    outPut << "[In] ";
                }
                if (attrs & PARAM_ATTRIBUTE_OUT) {
                    outPut << "[Out] ";
                }
            }
            auto parameter_class = il2cpp_class_from_type(param);
            outPut << il2cpp_class_get_name(parameter_class) << " "
                   << il2cpp_method_get_param_name(method, i);
            outPut << ", ";
        }
        if (param_count > 0) {
            outPut.seekp(-2, outPut.cur);
        }
        outPut << ") { }\n";
    }
    return outPut.str();
}

std::string dump_property(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Properties\n";
    void *iter = nullptr;
    while (auto prop_const = il2cpp_class_get_properties(klass, &iter)) {
        auto prop = const_cast<PropertyInfo *>(prop_const);
        auto get = il2cpp_property_get_get_method(prop);
        auto set = il2cpp_property_get_set_method(prop);
        auto prop_name = il2cpp_property_get_name(prop);
        outPut << "\t";
        Il2CppClass *prop_class = nullptr;
        uint32_t iflags = 0;
        if (get) {
            outPut << get_method_modifier(il2cpp_method_get_flags(get, &iflags));
            prop_class = il2cpp_class_from_type(il2cpp_method_get_return_type(get));
        } else if (set) {
            outPut << get_method_modifier(il2cpp_method_get_flags(set, &iflags));
            auto param = il2cpp_method_get_param(set, 0);
            prop_class = il2cpp_class_from_type(param);
        }
        if (prop_class) {
            outPut << il2cpp_class_get_name(prop_class) << " " << prop_name << " { ";
            if (get) {
                outPut << "get; ";
            }
            if (set) {
                outPut << "set; ";
            }
            outPut << "}\n";
        } else {
            if (prop_name) {
                outPut << " // unknown property " << prop_name;
            }
        }
    }
    return outPut.str();
}

std::string dump_field(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Fields\n";
    auto is_enum = il2cpp_class_is_enum(klass);
    void *iter = nullptr;
    while (auto field = il2cpp_class_get_fields(klass, &iter)) {
        outPut << "\t";
        auto attrs = il2cpp_field_get_flags(field);
        auto access = attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access) {
            case FIELD_ATTRIBUTE_PRIVATE:
                outPut << "private ";
                break;
            case FIELD_ATTRIBUTE_PUBLIC:
                outPut << "public ";
                break;
            case FIELD_ATTRIBUTE_FAMILY:
                outPut << "protected ";
                break;
            case FIELD_ATTRIBUTE_ASSEMBLY:
            case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                outPut << "internal ";
                break;
            case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                outPut << "protected internal ";
                break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL) {
            outPut << "const ";
        } else {
            if (attrs & FIELD_ATTRIBUTE_STATIC) {
                outPut << "static ";
            }
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY) {
                outPut << "readonly ";
            }
        }
        auto field_type = il2cpp_field_get_type(field);
        auto field_class = il2cpp_class_from_type(field_type);
        outPut << il2cpp_class_get_name(field_class) << " " << il2cpp_field_get_name(field);
        if (attrs & FIELD_ATTRIBUTE_LITERAL && is_enum) {
            uint64_t val = 0;
            il2cpp_field_static_get_value(field, &val);
            outPut << " = " << std::dec << val;
        }
        outPut << "; // 0x" << std::hex << il2cpp_field_get_offset(field) << "\n";
    }
    return outPut.str();
}

std::string dump_type(const Il2CppType *type) {
    std::stringstream outPut;
    auto *klass = il2cpp_class_from_type(type);
    outPut << "\n// Namespace: " << il2cpp_class_get_namespace(klass) << "\n";
    auto flags = il2cpp_class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) {
        outPut << "[Serializable]\n";
    }
    auto is_valuetype = il2cpp_class_is_valuetype(klass);
    auto is_enum = il2cpp_class_is_enum(klass);
    auto visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility) {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:
            outPut << "public ";
            break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
            outPut << "internal ";
            break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE:
            outPut << "private ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY:
            outPut << "protected ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "static ";
    } else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && flags & TYPE_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
    } else if (!is_valuetype && !is_enum && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "sealed ";
    }
    if (flags & TYPE_ATTRIBUTE_INTERFACE) {
        outPut << "interface ";
    } else if (is_enum) {
        outPut << "enum ";
    } else if (is_valuetype) {
        outPut << "struct ";
    } else {
        outPut << "class ";
    }
    outPut << il2cpp_class_get_name(klass); 
    std::vector<std::string> extends;
    auto parent = il2cpp_class_get_parent(klass);
    if (!is_valuetype && !is_enum && parent) {
        auto parent_type = il2cpp_class_get_type(parent);
        if (parent_type->type != IL2CPP_TYPE_OBJECT) {
            extends.emplace_back(il2cpp_class_get_name(parent));
        }
    }
    void *iter = nullptr;
    while (auto itf = il2cpp_class_get_interfaces(klass, &iter)) {
        extends.emplace_back(il2cpp_class_get_name(itf));
    }
    if (!extends.empty()) {
        outPut << " : " << extends[0];
        for (int i = 1; i < extends.size(); ++i) {
            outPut << ", " << extends[i];
        }
    }
    outPut << "\n{";
    outPut << dump_field(klass);
    outPut << dump_property(klass);
    outPut << dump_method(klass);
    outPut << "}\n";
    return outPut.str();
}

// ==============================================================================
// === 원본 init_il2cpp_api 함수 정의 (실제 내용) ===
// ==============================================================================
void init_il2cpp_api(void *handle) {
#define DO_API(r, n, p) {                      \
    n = (r (*) p)xdl_sym(handle, #n, nullptr); \
    if(!n) {                                   \
        LOGW("api not found %s", #n);          \
    }                                          \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}

// ==============================================================================
// === 수정된 il2cpp_dump 함수 ===
// ==============================================================================
void il2cpp_dump(const char *outDir) {
    LOGI("dumping...");

    // --- 추가된 덤프 로직 ---
    std::string out_dir_files = std::string(outDir) + "/files";
    mkdir(out_dir_files.c_str(), 0755); // /files 디렉토리 생성 확인

    // 1. libil2cpp.so 덤프
    std::string lib_out_path = out_dir_files + "/libil2cpp.so";
    dump_memory_region(il2cpp_base, il2cpp_size, lib_out_path.c_str());

    // 2. global-metadata.dat 덤프 (메모리 스캔 방식)
    std::string metadata_out_path = out_dir_files + "/global-metadata.dat";
    dump_metadata_from_memory(metadata_out_path.c_str());
    // --- 추가된 덤프 로직 끝 ---


    // --- 원본 dump.cs 생성 로직 ---
    LOGI("dumping classes, methods, etc. to dump.cs");
    size_t size;
    auto domain = il2cpp_domain_get();
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
    std::stringstream imageOutput;
    for (int i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
    }
    std::vector<std::string> outPuts;
    if (il2cpp_image_get_class) {
        LOGI("Version greater than 2018.3");
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            imageStr << "\n// Dll : " << il2cpp_image_get_name(image);
            auto classCount = il2cpp_image_get_class_count(image);
            for (int j = 0; j < classCount; ++j) {
                auto klass = il2cpp_image_get_class(image, j);
                auto type = il2cpp_class_get_type(const_cast<Il2CppClass *>(klass));
                auto outPut = imageStr.str() + dump_type(type);
                outPuts.push_back(outPut);
            }
        }
    } else {
        LOGI("Version less than 2018.3");
        auto corlib = il2cpp_get_corlib();
        auto assemblyClass = il2cpp_class_from_name(corlib, "System.Reflection", "Assembly");
        auto assemblyLoad = il2cpp_class_get_method_from_name(assemblyClass, "Load", 1);
        auto assemblyGetTypes = il2cpp_class_get_method_from_name(assemblyClass, "GetTypes", 0);
        if (assemblyLoad && assemblyLoad->methodPointer) {
            LOGI("Assembly::Load: %p", assemblyLoad->methodPointer);
        } else {
            LOGI("miss Assembly::Load");
            return;
        }
        if (assemblyGetTypes && assemblyGetTypes->methodPointer) {
            LOGI("Assembly::GetTypes: %p", assemblyGetTypes->methodPointer);
        } else {
            LOGI("miss Assembly::GetTypes");
            return;
        }
        typedef void *(*Assembly_Load_ftn)(void *, Il2CppString *, void *);
        typedef Il2CppArray *(*Assembly_GetTypes_ftn)(void *, void *);
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            auto image_name = il2cpp_image_get_name(image);
            imageStr << "\n// Dll : " << image_name;
            auto imageName = std::string(image_name);
            auto pos = imageName.rfind('.');
            auto imageNameNoExt = imageName.substr(0, pos);
            auto assemblyFileName = il2cpp_string_new(imageNameNoExt.data());
            auto reflectionAssembly = ((Assembly_Load_ftn) assemblyLoad->methodPointer)(nullptr,
                                                                                        assemblyFileName,
                                                                                        nullptr);
            auto reflectionTypes = ((Assembly_GetTypes_ftn) assemblyGetTypes->methodPointer)(
                    reflectionAssembly, nullptr);
            auto items = reflectionTypes->vector;
            for (int j = 0; j < reflectionTypes->max_length; ++j) {
                auto klass = il2cpp_class_from_system_type((Il2CppReflectionType *) items[j]);
                auto type = il2cpp_class_get_type(klass);
                auto outPut = imageStr.str() + dump_type(type);
                outPuts.push_back(outPut);
            }
        }
    }
    LOGI("write dump file");
    auto outPath = std::string(outDir).append("/files/dump.cs");
    std::ofstream outStream(outPath);
    outStream << imageOutput.str();
    auto count = outPuts.size();
    for (int i = 0; i < count; ++i) {
        outStream << outPuts[i];
    }
    outStream.close();
    LOGI("dump done!");
}
