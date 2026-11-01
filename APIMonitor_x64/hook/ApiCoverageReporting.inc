        CoveragePacket MakeCoverageRow(const wchar_t* module, const wchar_t* api, HookKind kind,
            CoverageState state, const wchar_t* detail, const InlineHookRecord* record)
        {
            CoveragePacket packet{};
            wcsncpy_s(packet.moduleName, module ? module : L"", _TRUNCATE);
            wcsncpy_s(packet.apiName, api ? api : L"", _TRUNCATE);
            wcsncpy_s(packet.detailText, detail ? detail : L"", _TRUNCATE);
            packet.apiId = RuntimeApiId(module, api);
            packet.hookKind = static_cast<std::uint32_t>(kind);
            packet.coverageState = static_cast<std::uint32_t>(state);
            if (record) packet.hookAddress = reinterpret_cast<std::uintptr_t>(record->targetAddress);
            return packet;
        }
        CoverageState StateForHook(const InlineHookRecord& record, const wchar_t* module,
            const char* api, bool enabled)
        {
            if (record.installed) return record.sharedEntry ? CoverageState::SharedEntry : CoverageState::Installed;
            if (!enabled) return CoverageState::CategoryDisabled;
            if (g_coverageRemovalInProgress && record.removed) return CoverageState::Removed;
            const auto image = ::GetModuleHandleW(module);
            if (!image) return CoverageState::WaitingModule;
            if (!::GetProcAddress(image, api)) return CoverageState::ExportMissing;
            return record.permanentlyDisabled ? CoverageState::Unsupported : CoverageState::RetryableFailure;
        }
        void CaptureRemovedRawCoverage()
        {
            for (const auto& row : RawBindings()) if (row)
            {
                g_rawCoverageObservations.erase(MakeRawHookKey(row->moduleName, row->procName));
                g_removedCoverageRows.push_back(MakeCoverageRow(row->moduleName.c_str(), row->procNameWide.c_str(),
                    HookKind::Raw, StateForHook(row->hookRecord, row->moduleName.c_str(), row->procName.c_str(),
                        ActiveConfig().enableRawFallback && CategoryEnabled(row->categoryValue)), row->hookRecord.lastFailure.c_str(), &row->hookRecord));
            }
        }
        void CaptureRemovedFakeCoverage()
        {
            for (const auto& row : FakeSuccessRules()) if (row)
                g_removedCoverageRows.push_back(MakeCoverageRow(row->installModuleName.c_str(), row->apiName.c_str(),
                    HookKind::Fake, StateForHook(row->hookRecord, row->installModuleName.c_str(), row->apiNameAnsi.c_str(),
                        ActiveConfig().fakeSuccessEnabled), row->hookRecord.lastFailure.c_str(), &row->hookRecord));
        }
        void PublishConfiguredCoverage()
        {
            std::vector<CoveragePacket> rows;
            rows.reserve(std::size(g_bindings) + RawBindings().size() + g_rawCoverageObservations.size());
            for (const auto& binding : g_bindings)
            {
                const auto name = AnsiToWide(binding.procName);
                const auto* fake = FindFakeSuccessRule(binding.moduleName, binding.procName);
                const auto state = fake ? CoverageState::RuleExcluded : StateForHook(*binding.hookRecord,
                    binding.moduleName, binding.procName, CategoryEnabled(binding.categoryValue) || NetworkCompletionObserver(binding));
                rows.push_back(MakeCoverageRow(binding.moduleName, name.c_str(), HookKind::Strong, state,
                    fake ? L"configured Fake handler replaces Strong handler"
                        : binding.hookRecord->installed && !CategoryEnabled(binding.categoryValue) && NetworkCompletionObserver(binding)
                            ? L"Network completion observer; File events disabled" : binding.hookRecord->lastFailure.c_str(), binding.hookRecord));
            }
            std::unordered_set<std::wstring> actualRawKeys;
            for (const auto& binding : RawBindings()) if (binding)
            {
                actualRawKeys.insert(MakeRawHookKey(binding->moduleName, binding->procName));
                rows.push_back(MakeCoverageRow(binding->moduleName.c_str(), binding->procNameWide.c_str(), HookKind::Raw,
                    StateForHook(binding->hookRecord, binding->moduleName.c_str(), binding->procName.c_str(),
                        ActiveConfig().enableRawFallback && CategoryEnabled(binding->categoryValue)),
                    binding->hookRecord.lastFailure.c_str(), &binding->hookRecord));
            }
            for (const auto& observation : g_rawCoverageObservations)
                if (!actualRawKeys.count(observation.first)) rows.push_back(observation.second);
            for (const auto& rule : FakeSuccessRules()) if (rule)
            {
                const bool known = IsStrongTypedExport(rule->installModuleName, rule->apiNameAnsi);
                const bool eligible = ActiveConfig().fakeSuccessEnabled && (known || ActiveConfig().fakeSuccessRawFallback);
                const auto state = eligible ? StateForHook(rule->hookRecord, rule->installModuleName.c_str(), rule->apiNameAnsi.c_str(), true)
                    : CoverageState::RuleExcluded;
                rows.push_back(MakeCoverageRow(rule->installModuleName.c_str(), rule->apiName.c_str(), HookKind::Fake,
                    state, eligible ? rule->hookRecord.lastFailure.c_str() : L"Raw Fake rule is not enabled", &rule->hookRecord));
            }
            AppendExtensionCoverage(rows);
            AppendWin32uClipboardCoverage(rows, g_coverageRemovalInProgress);
            rows.insert(rows.end(), g_removedCoverageRows.begin(), g_removedCoverageRows.end());
            std::sort(rows.begin(), rows.end(), [](const CoveragePacket& a, const CoveragePacket& b) {
                if (a.hookKind != b.hookKind) return a.hookKind < b.hookKind;
                const int module = wcscmp(a.moduleName, b.moduleName); if (module) return module < 0;
                const int api = wcscmp(a.apiName, b.apiName); if (api) return api < 0;
                return a.hookAddress < b.hookAddress;
            });
            PublishCoverageSnapshot(std::move(rows));
        }
