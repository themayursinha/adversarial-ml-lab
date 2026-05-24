"""Image model utilities for adversarial attack demonstrations."""

from __future__ import annotations

import numpy as np


def create_random_image(size: int = 224, channels: int = 3) -> np.ndarray:
    return np.random.rand(channels, size, size).astype(np.float32)


def load_model(name: str = "resnet18"):
    try:
        import torch  # noqa: F401 - required for torchvision
        from torchvision import models
    except ImportError as exc:
        raise ImportError(
            "torch and torchvision required for image attacks. "
            "Install: pip install torch torchvision"
        ) from exc

    if name == "resnet18":
        model = models.resnet18(weights=models.ResNet18_Weights.IMAGENET1K_V1)
    elif name == "mobilenet":
        model = models.mobilenet_v2(weights=models.MobileNet_V2_Weights.IMAGENET1K_V1)
    else:
        model = models.resnet18(weights=models.ResNet18_Weights.IMAGENET1K_V1)

    model.eval()
    return model


def preprocess_image(image: np.ndarray, size: int = 224) -> np.ndarray:
    import torch
    from torchvision import transforms

    if image.ndim == 3 and image.shape[0] in (1, 3):
        image_t = torch.from_numpy(image).float()
        if image_t.max() > 1.0:
            image_t = image_t / 255.0
        transform = transforms.Compose(
            [
                transforms.Resize((size, size), antialias=True),
                transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
            ]
        )
        return transform(image_t).numpy()  # type: ignore[no-any-return]
    return image
