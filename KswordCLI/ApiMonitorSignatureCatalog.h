#pragma once

#include "../shared/ApiMonitorCliView.h"
#include "../shared/evidence/EvidenceJson.h"
#include <Wincrypt.h>
#include <filesystem>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace ks::cli {
struct CliSignatureParameter { std::wstring name, type, direction; };
struct CliSignature {
    std::wstring module, function, callingConvention, returnType, source, sourceFile, abiEvidence;
    std::vector<CliSignatureParameter> parameters;
};
class CliSignatureCatalog final {
    using Value=Ksword::Evidence::JsonValue;
    using Key=std::pair<std::wstring,std::wstring>;
    std::map<Key,CliSignature,ks::winapi_monitor::CliApiLess> signatures;
    static std::wstring wideUtf8(const std::string& value) {
        if(value.empty() || value.size()>2048) throw std::invalid_argument("invalid signature text");
        const int needed=::MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0);
        if(!needed)throw std::invalid_argument("invalid signature UTF-8");
        std::wstring out(static_cast<std::size_t>(needed),L'\0');
        if(::MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),out.data(),needed)!=needed)
            throw std::invalid_argument("invalid signature UTF-8");
        if(out.find(L'\x1f')!=std::wstring::npos || out.find(L'\0')!=std::wstring::npos)throw std::invalid_argument("invalid signature text");
        return out;
    }
    static std::wstring string(const Value* value) {
        std::string s;if(!value || !value->tryGetString(s))throw std::invalid_argument("invalid signature field");
        return wideUtf8(s);
    }
    static const Ksword::Evidence::JsonArray& array(const Value* value) {
        if(!value || !value->asArray())throw std::invalid_argument("invalid signature array");return *value->asArray();
    }
    static std::string digest(const std::string& data) {
        HCRYPTPROV provider=0;HCRYPTHASH hash=0;BYTE bytes[32]{};DWORD size=sizeof(bytes);
        if(!::CryptAcquireContextW(&provider,nullptr,nullptr,PROV_RSA_AES,CRYPT_VERIFYCONTEXT))throw std::runtime_error("signature SHA-256 provider unavailable");
        const bool ok=::CryptCreateHash(provider,CALG_SHA_256,0,0,&hash)
            && ::CryptHashData(hash,reinterpret_cast<const BYTE*>(data.data()),static_cast<DWORD>(data.size()),0)
            && ::CryptGetHashParam(hash,HP_HASHVAL,bytes,&size,0) && size==sizeof(bytes);
        if(hash)::CryptDestroyHash(hash);::CryptReleaseContext(provider,0);
        if(!ok)throw std::runtime_error("signature SHA-256 failed");
        constexpr char digits[]="0123456789abcdef";std::string out;out.reserve(64);
        for(auto b:bytes){out+=digits[b>>4];out+=digits[b&15];}return out;
    }
    void insert(CliSignature value) {
        const Key key{ks::winapi_monitor::cliModuleIdentity(value.module),value.function};
        if(!signatures.emplace(key,std::move(value)).second)throw std::invalid_argument("duplicate signature identity");
    }
public:
    std::wstring filePath;
    std::string sha256;
    void load(const std::filesystem::path& path) {
        std::error_code error;const auto size=std::filesystem::file_size(path,error);
        if(error || !size || size>16*1024*1024)throw std::invalid_argument("signature catalog must be readable and 1..16 MiB");
        std::ifstream file(path,std::ios::binary);if(!file)throw std::invalid_argument("cannot open signature catalog");
        std::string data(static_cast<std::size_t>(size),'\0');
        if(!file.read(data.data(),static_cast<std::streamsize>(data.size())) || file.peek()!=std::char_traits<char>::eof())
            throw std::invalid_argument("signature catalog changed during read");
        const auto checksum=digest(data);
        Ksword::Evidence::JsonLimits limits;limits.maxTotalBytes=16*1024*1024;limits.maxTotalNodes=1000000;
        limits.maxEstimatedNodeBytes=160u*1024u*1024u;
        const auto parsed=Ksword::Evidence::ParseJson(data,limits);
        if(!parsed.ok())throw std::invalid_argument("invalid or oversized signature catalog JSON");
        std::uint64_t version=0;const auto* schema=parsed.value.find("schema_version");
        if(!schema || !schema->tryGetU64(version) || version!=1)throw std::invalid_argument("unsupported signature catalog schema");
        const auto& owned=array(parsed.value.find("apis"));if(owned.size()>65536)throw std::invalid_argument("too many signatures");
        signatures.clear();
        for(const auto& row:owned) {
            CliSignature s;s.module=string(row.find("module"));s.function=string(row.find("export"));
            s.callingConvention=string(row.find("calling_convention"));s.returnType=string(row.find("return_type"));
            s.source=L"project strong-hook declaration";s.abiEvidence=L"project";
            const auto& params=array(row.find("parameters"));if(params.size()>64)throw std::invalid_argument("too many parameters");
            for(const auto& p:params)s.parameters.push_back({string(p.find("name")),string(p.find("type")),string(p.find("direction"))});
            insert(std::move(s));
        }
        const auto* refs=parsed.value.find("reference_signatures");
        if(refs) {
            std::uint64_t referenceVersion=0;const auto* referenceSchema=refs->find("schema_version");
            if(!referenceSchema || referenceSchema->type()!=Ksword::Evidence::JsonType::UInt
                || !referenceSchema->tryGetU64(referenceVersion) || referenceVersion!=1)
                throw std::invalid_argument("unsupported reference signature schema");
            const auto status=string(refs->find("status"));if(status!=L"unverified")throw std::invalid_argument("invalid reference status");
            const auto& rows=array(refs->find("entries"));if(rows.size()>65536 || rows.size()+owned.size()>65536)throw std::invalid_argument("too many references");
            for(const auto& row:rows) {
                const auto& f=array(&row);if(f.size()!=6)throw std::invalid_argument("invalid reference entry");
                CliSignature s;s.module=string(&f[0]);s.function=string(&f[1]);s.callingConvention=string(&f[2]);
                s.returnType=string(&f[3]);s.sourceFile=string(&f[5]);s.source=L"API Monitor XML reference";s.abiEvidence=L"unverified";
                const auto& params=array(&f[4]);if(params.size()>64)throw std::invalid_argument("too many reference parameters");
                for(const auto& p:params){const auto& fields=array(&p);if(fields.size()!=2)throw std::invalid_argument("invalid reference parameter");s.parameters.push_back({string(&fields[0]),string(&fields[1]),L"unknown"});}
                insert(std::move(s));
            }
            const auto* verified=refs->find("verified_abis");
            if(verified) {
                (void)string(verified->find("sdk"));(void)string(verified->find("header_sha256"));
                const auto& entries=array(verified->find("entries"));if(entries.size()>rows.size())throw std::invalid_argument("invalid verified entries");
                for(const auto& entry:entries) {
                    const auto& f=array(&entry);if(f.size()!=5)throw std::invalid_argument("invalid verified entry");
                    const auto module=string(&f[0]);const auto function=string(&f[1]);
                    const auto it=signatures.find({ks::winapi_monitor::cliModuleIdentity(module),function});
                    if(it==signatures.end() || it->second.abiEvidence!=L"unverified")throw std::invalid_argument("invalid verified identity");
                    auto& s=it->second;s.returnType=string(&f[2]);s.callingConvention=string(&f[3]);
                    if(s.callingConvention!=L"WINAPI")throw std::invalid_argument("invalid verified convention");
                    const auto& params=array(&f[4]);if(params.size()!=s.parameters.size())throw std::invalid_argument("invalid verified parameters");
                    for(std::size_t i=0;i<params.size();++i)s.parameters[i].type=string(&params[i]);
                    s.abiEvidence=L"Windows SDK x86/x64";
                }
            }
        }
        filePath=path.wstring();sha256=checksum;
    }
    const CliSignature* find(const std::wstring& module,const std::wstring& function) const {
        const auto it=signatures.find({ks::winapi_monitor::cliModuleIdentity(module),function});
        return it==signatures.end()?nullptr:&it->second;
    }
    std::size_t size() const { return signatures.size(); }
};
}
