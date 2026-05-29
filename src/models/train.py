import os
import logging
from typing import List, Dict, Any
import torch
from torch.utils.data import Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments

logger = logging.getLogger(__name__)

class CodeVulnerabilityDataset(Dataset):
    def __init__(self, encodings: Dict[str, Any], labels: List[int]) -> None:
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item['labels'] = torch.tensor(self.labels[idx])
        return item

    def __len__(self) -> int:
        return len(self.labels)

class ModelTrainer:
    def __init__(self, model_name: str = "microsoft/codebert-base", output_dir: str = "./results") -> None:
        self.model_name = model_name
        self.output_dir = output_dir
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)

    def train(self, train_records: List[Dict[str, Any]], val_records: List[Dict[str, Any]], epochs: int = 3, batch_size: int = 8) -> None:
        """
        Tokenizes datasets, configures training args, and triggers HuggingFace Trainer.
        """
        logger.info("Tokenizing datasets...")
        
        train_texts = [r["code_sample"] for r in train_records]
        train_labels = [r["is_vulnerable"] for r in train_records]
        
        val_texts = [r["code_sample"] for r in val_records]
        val_labels = [r["is_vulnerable"] for r in val_records]

        train_encodings = self.tokenizer(train_texts, truncation=True, padding=True, max_length=512)
        val_encodings = self.tokenizer(val_texts, truncation=True, padding=True, max_length=512)

        train_dataset = CodeVulnerabilityDataset(train_encodings, train_labels)
        val_dataset = CodeVulnerabilityDataset(val_encodings, val_labels)

        # Detect mixed precision support
        fp16_enabled = torch.cuda.is_available()
        
        training_args = TrainingArguments(
            output_dir=self.output_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            warmup_steps=100,
            weight_decay=0.01,
            logging_dir='./logs',
            logging_steps=10,
            eval_strategy="epoch",
            save_strategy="epoch",
            fp16=fp16_enabled,
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            greater_is_better=False,
            gradient_accumulation_steps=2 if batch_size < 16 else 1,
            dataloader_num_workers=2 if torch.cuda.is_available() else 0
        )

        model = AutoModelForSequenceClassification.from_pretrained(self.model_name, num_labels=2)
        
        if torch.cuda.is_available():
            model = model.to("cuda")

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
        )

        logger.info("Starting HuggingFace fine-tuning model training...")
        trainer.train()
        
        # Save model and tokenizer assets
        model.save_pretrained(self.output_dir)
        self.tokenizer.save_pretrained(self.output_dir)
        logger.info("Model training completed and outputs saved to %s.", self.output_dir)
