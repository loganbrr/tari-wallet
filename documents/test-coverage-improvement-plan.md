# Tari Wallet Test Coverage Improvement Plan

## Executive Summary
**Current Coverage**: 36.54% (2,877/7,874 lines)  
**Target Coverage**: 80%+ (6,299+ lines)  
**Timeline**: 6 weeks  
**Expected Impact**: +43.46% coverage improvement

## Current State Analysis

### Coverage Breakdown by Module
```
Critical Infrastructure (Low Coverage):
├── Storage: src/storage/sqlite.rs (32.7% - 324/990 lines)
├── Scanning: src/scanning/* (22.7% average)
└── CLI Binaries: src/bin/* (0% - 1,882 lines uncovered)

Well-Tested Modules (High Coverage):
├── Address: src/data_structures/address.rs (69.4% - 283/408 lines)  
├── Crypto: src/crypto/signing.rs (66.7% - 22/33 lines)
└── Key Management: src/key_management/* (78.9% average)

Medium Coverage Modules:
├── Validation: src/validation/* (70.2% average)
├── Extraction: src/extraction/* (58.7% average)
└── Data Structures: src/data_structures/* (62.1% average)
```

## Phase-by-Phase Implementation Plan

### Phase 1: Critical Infrastructure Testing
**Duration**: 2 weeks  
**Impact**: +20% coverage  
**Priority**: HIGH

#### 1.1 Storage Module Enhancement
**Files**: `src/storage/sqlite.rs`, `src/storage/storage_trait.rs`
**Current**: 341/1,102 lines (30.9%)
**Target**: 882/1,102 lines (80%)

**Task Breakdown**:
- [ ] **Database Connection Testing** (3 days)
  - Connection pool exhaustion scenarios
  - Database file corruption recovery
  - Concurrent transaction handling
  - Connection timeout validation

- [ ] **SQLite Operations Coverage** (4 days)
  - CRUD operations for all entity types
  - Complex query validation (joins, filters)
  - Transaction rollback scenarios
  - Schema migration testing
  - Batch operation performance tests

- [ ] **Storage Trait Implementation** (2 days)
  - Mock storage implementations for testing
  - Storage interface validation
  - Error propagation testing

#### 1.2 Scanning Module Enhancement  
**Files**: `src/scanning/grpc_scanner.rs`, `src/scanning/http_scanner.rs`, `src/scanning/mod.rs`
**Current**: 146/1,124 lines (13.0%)
**Target**: 899/1,124 lines (80%)

**Task Breakdown**:
- [ ] **GRPC Scanner Testing** (4 days)
  - Mock GRPC server setup
  - Network failure simulation
  - Block parsing edge cases
  - Parallel scanning validation
  - Rate limiting behavior

- [ ] **HTTP Scanner Testing** (3 days)
  - HTTP client mocking framework
  - JSON parsing error handling
  - Retry mechanism validation
  - Timeout scenario testing

### Phase 2: CLI Binary Testing Framework
**Duration**: 1 week  
**Impact**: +15% coverage  
**Priority**: HIGH

#### 2.1 Binary Testing Infrastructure
**Files**: `src/bin/scanner.rs`, `src/bin/wallet.rs`, `src/bin/signing.rs`
**Current**: 0/1,882 lines (0%)
**Target**: 1,317/1,882 lines (70%)

**Task Breakdown**:
- [ ] **CLI Testing Framework Setup** (2 days)
  - Integration test harness using `std::process::Command`
  - Mock blockchain endpoint infrastructure
  - Test database and file system isolation
  - Output capture and validation utilities

- [ ] **Scanner Binary Testing** (2 days)
  - Command-line argument validation
  - Configuration file parsing
  - Network endpoint connectivity
  - Progress reporting and error handling
  - Exit code verification

- [ ] **Wallet Binary Testing** (2 days)
  - Wallet creation and management commands
  - Address generation and validation
  - Import/export functionality
  - Balance and transaction queries

- [ ] **Signing Binary Testing** (1 day)
  - Message signing workflows
  - Key import/export operations
  - Cryptographic validation

### Phase 3: Data Structure Coverage Enhancement
**Duration**: 1 week  
**Impact**: +10% coverage  
**Priority**: MEDIUM

#### 3.1 Core Data Structures
**Files**: `src/data_structures/block.rs`, `src/data_structures/wallet_output.rs`, `src/data_structures/types.rs`
**Current**: 211/504 lines (41.9%)
**Target**: 403/504 lines (80%)

**Task Breakdown**:
- [ ] **Block Data Structure Testing** (2 days)
  - Block parsing from various formats
  - Input processing edge cases
  - Validation rule enforcement
  - Serialization round-trip testing

- [ ] **Wallet Output Testing** (2 days)
  - Output type classification
  - Spending condition validation
  - Maturity and lock height logic
  - Output ordering and comparison

- [ ] **Type System Validation** (3 days)
  - SafeArray security validation
  - Commitment and key type testing
  - MicroMinotari arithmetic operations
  - Hex encoding/decoding edge cases

### Phase 4: Integration & End-to-End Testing
**Duration**: 1 week  
**Impact**: +8% coverage  
**Priority**: MEDIUM

#### 4.1 Workflow Integration Tests
**New Files**: `tests/integration/`, `tests/e2e/`
**Target**: Full workflow coverage

**Task Breakdown**:
- [ ] **Complete Wallet Workflow** (3 days)
  - Wallet creation → key derivation → address generation
  - Scanning → UTXO discovery → balance calculation
  - Transaction creation → signing → broadcasting

- [ ] **Multi-Network Testing** (2 days)
  - Cross-network compatibility validation
  - Address format consistency across networks
  - Configuration parameter validation

- [ ] **Performance & Stress Testing** (2 days)
  - Large dataset processing
  - Memory usage profiling
  - Concurrent operation validation

### Phase 5: Error Handling & Edge Cases
**Duration**: 1 week  
**Impact**: +6% coverage  
**Priority**: LOW

#### 5.1 Error Path Coverage
**Files**: `src/errors.rs`, `src/extraction/corruption_detection.rs`
**Current**: 150/404 lines (37.1%)
**Target**: 323/404 lines (80%)

**Task Breakdown**:
- [ ] **Error Type Validation** (2 days)
  - Error conversion and propagation
  - Error message consistency
  - Debug and display formatting

- [ ] **Corruption Detection Enhancement** (3 days)
  - Malformed data handling
  - Byzantine input scenarios
  - Recovery mechanism validation
  - False positive/negative testing

## Implementation Standards

### Test Quality Requirements
- **Unit Tests**: Fast (<100ms), isolated, deterministic
- **Integration Tests**: Medium speed (<5s), real component interaction
- **E2E Tests**: Slower acceptable (<30s), full workflow validation
- **Coverage Goal**: 80% line coverage, 90% branch coverage for critical paths

### Testing Infrastructure
- **Mocking Strategy**: Use `mockall` for external dependencies
- **Test Data**: Deterministic test vectors in `tests/fixtures/`
- **CI Integration**: Coverage reporting in GitHub Actions
- **Performance**: Parallel test execution where safe

### Security Testing Focus
- **Cryptographic Validation**: Real crypto operations, not stubs
- **Memory Safety**: Zeroize verification for sensitive data
- **Input Sanitization**: Malformed data handling
- **Side-Channel Resistance**: Timing attack prevention

## Success Metrics

### Quantitative Targets
- **Overall Coverage**: 36.54% → 80%+
- **Critical Module Coverage**: Storage (32.7% → 80%), Scanning (22.7% → 80%)
- **Binary Coverage**: 0% → 70%
- **Test Execution Time**: <5 minutes for full suite
- **CI Success Rate**: >95% test reliability

### Qualitative Improvements
- **Bug Detection**: Catch regressions before release
- **Code Confidence**: Safer refactoring capabilities
- **Documentation**: Living examples through tests
- **Onboarding**: New developers can understand system through tests

## Resource Requirements

### Development Time
- **Phase 1**: 80 hours (2 weeks × 40 hours)
- **Phase 2**: 40 hours (1 week × 40 hours)  
- **Phase 3**: 40 hours (1 week × 40 hours)
- **Phase 4**: 40 hours (1 week × 40 hours)
- **Phase 5**: 40 hours (1 week × 40 hours)
- **Total**: 240 hours (6 weeks)

### Infrastructure Needs
- **Mock Services**: Local blockchain simulation
- **Test Databases**: Isolated SQLite instances
- **CI/CD**: Coverage reporting integration
- **Documentation**: Test writing guidelines

## Risk Mitigation

### Technical Risks
- **Mock Complexity**: Keep mocks simple, focus on behavior not implementation
- **Test Maintenance**: Prioritize maintainable tests over maximum coverage
- **Performance Impact**: Optimize test suite for CI/CD pipeline speed
- **Flaky Tests**: Eliminate non-deterministic behavior

### Timeline Risks
- **Scope Creep**: Stick to coverage targets, avoid perfectionism
- **Dependency Delays**: Mock external dependencies to avoid blocking
- **Resource Allocation**: Plan for interrupted development time

## Verification & Validation

### Continuous Monitoring
- **Daily**: Coverage reports in CI/CD
- **Weekly**: Test execution performance analysis
- **Phase Completion**: Coverage milestone validation
- **Project Completion**: Full regression test suite execution

### Quality Gates
- **Phase 1**: Storage and scanning modules >80% coverage
- **Phase 2**: All binaries >70% coverage  
- **Phase 3**: Core data structures >80% coverage
- **Final**: Overall project >80% coverage with <5min test execution

---

**Document Version**: 1.0  
**Last Updated**: 2025-07-21  
**Next Review**: End of Phase 1
