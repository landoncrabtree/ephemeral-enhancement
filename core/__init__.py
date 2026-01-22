"""
Core pipeline functionality.

This package contains the modular components of the cipher brute-forcing pipeline:
- args: Argument parsing and configuration
- pipeline: Pipeline parsing and validation
- executor: Stage execution logic
- worker: Worker state and chunk processing
- parallel: Parallel execution orchestration
- utils: Utility functions
"""

from .args import PipelineConfig, create_argument_parser, parse_args
from .executor import StageExecutor
from .parallel import ExecutionResults, ParallelExecutor, display_results
from .pipeline import (
    VALID_STAGES,
    StageAxis,
    axes_for_pipeline,
    parse_pipeline,
    validate_pipeline,
)
from .utils import (
    limit_keys,
    load_common_words,
    load_dictionary,
    mixed_radix_unrank,
)
from .worker import WorkerState, init_worker, process_chunk

__all__ = [
    # args
    "PipelineConfig",
    "create_argument_parser",
    "parse_args",
    # pipeline
    "VALID_STAGES",
    "StageAxis",
    "parse_pipeline",
    "axes_for_pipeline",
    "validate_pipeline",
    # executor
    "StageExecutor",
    # worker
    "WorkerState",
    "init_worker",
    "process_chunk",
    # parallel
    "ParallelExecutor",
    "ExecutionResults",
    "display_results",
    # utils
    "load_dictionary",
    "limit_keys",
    "load_common_words",
    "mixed_radix_unrank",
]
