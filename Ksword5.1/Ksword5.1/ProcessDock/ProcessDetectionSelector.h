#pragma once

#include "ProcessDetectionMethods.h"
#include <QPushButton>

namespace ksword::detection
{
    class ProcessDetectionSelector final : public QPushButton
    {
    public:
        explicit ProcessDetectionSelector(bool deep, QWidget* parent = nullptr);
        MethodMask selectedMethods() const { return m_selected; }
        ScanInputs scanInputs() const { return m_inputs; }

    private:
        void edit();
        void updateCaption();
        bool m_deep;
        MethodMask m_selected;
        ScanInputs m_inputs;
    };
}
