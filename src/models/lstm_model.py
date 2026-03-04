from typing import Tuple
import tensorflow as tf
from tensorflow.keras import layers, models

def build_lstm_model(
    input_shape: Tuple[int, int],
    lstm_units: int = 64,
    dropout: float = 0.3
) -> tf.keras.Model:
    inputs = layers.Input(shape=input_shape)
    x = layers.Masking(mask_value=0.0)(inputs)
    x = layers.LSTM(lstm_units)(x)
    x = layers.Dropout(dropout)(x)
    x = layers.Dense(32, activation="relu")(x)
    x = layers.Dropout(dropout)(x)
    outputs = layers.Dense(1, activation="sigmoid")(x)

    model = models.Model(inputs, outputs)
    model.compile(
        optimizer=tf.keras.optimizers.Adam(),
        loss="binary_crossentropy",
        metrics=["accuracy", tf.keras.metrics.AUC(name="auc")],
    )
    return model