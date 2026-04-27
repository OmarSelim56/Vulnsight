import torch
import torch.nn as nn

class HybridCNNBiLSTM(nn.Module):
    def __init__(self, feature_size=20, num_classes=2):
        super(HybridCNNBiLSTM, self).__init__()
        
        # 1. CNN Layer
        self.cnn = nn.Conv1d(in_channels=feature_size, out_channels=64, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        
        # 2. BiLSTM
        self.lstm = nn.LSTM(
            input_size=64, 
            hidden_size=128, 
            num_layers=2, 
            batch_first=True, 
            bidirectional=True,
            dropout=0.3
        )
        
        # 3. Fully Connected Layers
        self.fc = nn.Sequential(
            nn.Linear(128 * 2, 64), 
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(64, num_classes)
        )

    def forward(self, x):
        # x: (Batch, 10, 20)
        x = x.permute(0, 2, 1) # -> (Batch, 20, 10)
        
        x = self.cnn(x)
        x = self.relu(x)

        x = x.permute(0, 2, 1)  # -> (Batch, 10, 64)
        
        lstm_out, _ = self.lstm(x)
        last_time_step = lstm_out[:, -1, :]
        
        return self.fc(last_time_step)