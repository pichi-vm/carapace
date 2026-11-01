// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Target root types defined by the Discoverable Partitions Specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    /// 64-bit x86 Linux root.
    X86_64,

    /// 64-bit ARM Linux root.
    Aarch64,
}

impl Architecture {
    pub(super) fn partition_type(self) -> gpt::partition_types::Type {
        match self {
            Self::X86_64 => gpt::partition_types::LINUX_ROOT_X64,
            Self::Aarch64 => gpt::partition_types::LINUX_ROOT_ARM_64,
        }
    }
}
