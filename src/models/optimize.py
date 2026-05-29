import logging
from typing import Dict, Any, Tuple
import torch

logger = logging.getLogger(__name__)

def detect_gpu_and_configure() -> Tuple[str, Dict[str, Any]]:
    """
    Detects GPU properties and builds an optimization configurations map.
    Optimizes specifically for T4, V100, A100, and H100 GPU tiers.
    """
    optimizations: Dict[str, Any] = {
        "mixed_precision": "fp16",
        "use_compile": False,
        "gradient_checkpointing": True,
        "quantization": None,
        "batch_multiplier": 1
    }
    
    if not torch.cuda.is_available():
        logger.info("No GPU detected. Defaulting to standard CPU configuration.")
        return "CPU", optimizations

    device_name = torch.cuda.get_device_name(0)
    logger.info("Detected GPU: %s", device_name)

    # Check capability
    major, minor = torch.cuda.get_device_capability(0)
    
    if major >= 8: # A100 / H100 / RTX 3090/4090
        logger.info("High-end GPU detected (Ampere/Hopper architecture). Optimizing for bfloat16 and flash-attention.")
        optimizations["mixed_precision"] = "bf16"
        optimizations["use_compile"] = True
        optimizations["batch_multiplier"] = 2
    elif major == 7: # V100 / T4 (T4 is 7.5, V100 is 7.0)
        logger.info("Mid-range GPU detected (Volta/Turing architecture). Enabling fp16 mixed precision.")
        optimizations["mixed_precision"] = "fp16"
        # torch.compile might have bugs on older CUDA runtimes, enable selectively
        optimizations["use_compile"] = True if "V100" in device_name else False
        optimizations["batch_multiplier"] = 1
    else: # Older GPUs (K80, P100, etc.)
        logger.info("Older generation GPU detected. Standard fp16 enabled with gradient checkpointing.")
        optimizations["mixed_precision"] = "fp16"
        optimizations["gradient_checkpointing"] = True

    return device_name, optimizations

def get_qlora_config() -> Any:
    """
    Builds the bitsandbytes BitsAndBytesConfig for 4-bit model quantization.
    Requires bitsandbytes and accelerate packages installed.
    """
    try:
        from transformers import BitsAndBytesConfig
        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_available() and torch.cuda.get_device_capability(0)[0] >= 8 else torch.float16
        )
        logger.info("BitsAndBytes 4-bit quantization config prepared.")
        return quant_config
    except ImportError:
        logger.warning("bitsandbytes or transformers not available for importing BitsAndBytesConfig. Skipping quantization.")
        return None

def apply_model_optimizations(model: Any, optimizations: Dict[str, Any]) -> Any:
    """
    Applies runtime model compilation and gradient checkpointing flags to the target model.
    """
    if optimizations.get("gradient_checkpointing") and hasattr(model, "gradient_checkpointing_enable"):
        model.gradient_checkpointing_enable()
        logger.info("Gradient checkpointing enabled on model.")

    if optimizations.get("use_compile"):
        try:
            logger.info("Running torch.compile() on the model...")
            model = torch.compile(model)
            logger.info("Model compiled successfully.")
        except Exception as e:
            logger.warning("Failed to compile model using torch.compile: %s. Continuing without JIT compilation.", str(e))
            
    return model
