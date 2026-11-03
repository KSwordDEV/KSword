#pragma once

#include "../shared/ApiMonitorCliView.h"
#include "../shared/evidence/EvidenceJson.h"
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace ks::cli {
struct ImportedApiFilters {
    ks::winapi_monitor::CliEventFilter pre, post;
};
inline ImportedApiFilters loadApiFilters(const std::filesystem::path& path) {
    using namespace Ksword::Evidence;
    std::error_code error;const auto size=std::filesystem::file_size(path,error);
    if(error || !size || size>4u*1024u*1024u)throw std::invalid_argument("filter file must be readable and 1..4 MiB");
    std::ifstream file(path,std::ios::binary);if(!file)throw std::invalid_argument("cannot open filter file");
    std::string data(static_cast<std::size_t>(size),'\0');
    if(!file.read(data.data(),static_cast<std::streamsize>(data.size())) || file.peek()!=std::char_traits<char>::eof())
        throw std::invalid_argument("filter file changed during read");
    if(data.size()>=3 && data.compare(0,3,"\xef\xbb\xbf")==0)data.erase(0,3);
    JsonLimits limits;limits.maxTotalBytes=4u*1024u*1024u;
    const auto parsed=ParseJson(data,limits);
    if(!parsed.ok())throw std::invalid_argument("invalid or oversized filter JSON");
    std::uint64_t version=0;const auto* versionValue=parsed.value.find("version");
    if(!versionValue || versionValue->type()!=JsonType::UInt || !versionValue->tryGetU64(version) || (version!=1 && version!=2))
        throw std::invalid_argument("unsupported filter version");
    const auto* rulesValue=parsed.value.find("rules");const auto* rows=rulesValue?rulesValue->asArray():nullptr;
    if(!rows || rows->size()>20000)throw std::invalid_argument("invalid filter rules");
    ImportedApiFilters out;
    const auto getText=[](const JsonValue* item)->std::wstring {
        std::string input;if(!item || !item->tryGetString(input) || input.size()>4096)throw std::invalid_argument("invalid filter name");
        if(input.empty())return {};
        const int n=::MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),nullptr,0);
        if(!n)throw std::invalid_argument("invalid filter UTF-8");
        std::wstring value(static_cast<std::size_t>(n),L'\0');
        if(::MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),value.data(),n)!=n)
            throw std::invalid_argument("invalid filter UTF-8");
        if(value.find(L'\x1f')!=std::wstring::npos || value.find(L'\0')!=std::wstring::npos)throw std::invalid_argument("invalid filter name");
        return ks::winapi_monitor::cliTrim(std::move(value));
    };
    const auto getBool=[](const JsonValue* item)->bool {
        bool value=false;if(!item || !item->tryGetBool(value))throw std::invalid_argument("invalid filter flag");return value;
    };
    for(const auto& row:*rows) {
        if(!row.asObject())throw std::invalid_argument("invalid filter row");
        auto module=getText(row.find("module"));auto function=getText(row.find("function"));
        if(module.empty() || module.size()>260 || function.size()>1024)throw std::invalid_argument("invalid filter identity");
        module=ks::winapi_monitor::cliModuleIdentity(std::move(module));
        const bool pre=getBool(row.find("pre")),post=getBool(row.find("post"));
        const bool preAllow=version==2?getBool(row.find("preAllow")):false;
        const bool postAllow=version==2?getBool(row.find("postAllow")):false;
        if(function.empty()) {
            if(preAllow || postAllow)throw std::invalid_argument("module allow exception is invalid");
            if(pre)out.pre.modules.insert(module);if(post)out.post.modules.insert(module);
        } else {
            const auto identity=std::make_pair(module,function);
            if(pre)out.pre.functions.insert(identity);if(post)out.post.functions.insert(identity);
            if(preAllow)out.pre.allowedFunctions.insert(identity);if(postAllow)out.post.allowedFunctions.insert(identity);
        }
    }
    return out;
}
}
