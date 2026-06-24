"""Image adversarial attacks: FGSM, PGD, Carlini-Wagner.

Demonstrates classic adversarial ML on vision models using PyTorch.
EDUCATIONAL PURPOSE ONLY.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np


@dataclass
class AdversarialImage:
    original: np.ndarray
    adversarial: np.ndarray
    perturbation: np.ndarray
    original_prediction: int
    adversarial_prediction: int
    original_confidence: float
    adversarial_confidence: float
    attack_name: str
    l2_distance: float
    linf_distance: float
    success: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_name": self.attack_name,
            "original_prediction": int(self.original_prediction),
            "adversarial_prediction": int(self.adversarial_prediction),
            "original_confidence": round(self.original_confidence, 4),
            "adversarial_confidence": round(self.adversarial_confidence, 4),
            "l2_distance": round(self.l2_distance, 6),
            "linf_distance": round(self.linf_distance, 6),
            "success": self.success,
            "perturbation_shape": list(self.perturbation.shape),
        }


class FastGradientSignMethod:
    """FGSM: single-step gradient-based attack (Goodfellow et al. 2014)."""

    def __init__(self, model: Any, epsilon: float = 0.03) -> None:
        self.model = model
        self.epsilon = epsilon

    def generate(self, image: np.ndarray, label: int) -> AdversarialImage:
        import torch

        x = torch.from_numpy(image).float().unsqueeze(0)
        x.requires_grad = True

        self.model.eval()
        with torch.enable_grad():
            output = self.model(x)
            loss = torch.nn.functional.cross_entropy(output, torch.tensor([label]))
            loss.backward()

        if x.grad is None:
            raise RuntimeError("FGSM attack failed: input gradient was not computed")
        grad_sign = x.grad.sign()
        adv = x + self.epsilon * grad_sign
        adv = torch.clamp(adv, 0, 1)

        with torch.no_grad():
            orig_out = self.model(x).softmax(dim=1)
            adv_out = self.model(adv).softmax(dim=1)
            orig_pred = int(orig_out.argmax(dim=1).item())
            adv_pred = int(adv_out.argmax(dim=1).item())
            orig_conf = float(orig_out[0, label].item())
            adv_conf = float(adv_out[0, label].item())

        adv_np = adv.detach().squeeze(0).numpy()
        pert = (adv_np - image).astype(np.float64)

        return AdversarialImage(
            original=image,
            adversarial=adv_np,
            perturbation=pert,
            original_prediction=orig_pred,
            adversarial_prediction=adv_pred,
            original_confidence=orig_conf,
            adversarial_confidence=adv_conf,
            attack_name="FGSM",
            l2_distance=float(np.sqrt(np.sum(pert**2))),
            linf_distance=float(np.max(np.abs(pert))),
            success=adv_pred != orig_pred,
        )


class ProjectedGradientDescent:
    """PGD: iterative FGSM with random start (Madry et al. 2017)."""

    def __init__(
        self,
        model: Any,
        epsilon: float = 0.03,
        alpha: float = 0.01,
        steps: int = 40,
    ) -> None:
        self.model = model
        self.epsilon = epsilon
        self.alpha = alpha
        self.steps = steps

    def generate(self, image: np.ndarray, label: int) -> AdversarialImage:
        import torch

        x = torch.from_numpy(image).float().unsqueeze(0)
        original = x.clone()

        noise = torch.rand_like(x) * 2 * self.epsilon - self.epsilon
        x_adv = torch.clamp(x + noise, 0, 1)

        self.model.eval()
        for _ in range(self.steps):
            x_adv = x_adv.detach().requires_grad_(True)
            with torch.enable_grad():
                output = self.model(x_adv)
                loss = torch.nn.functional.cross_entropy(output, torch.tensor([label]))
                loss.backward()

            with torch.no_grad():
                if x_adv.grad is None:
                    raise RuntimeError("PGD attack failed: input gradient was not computed")
                x_adv = x_adv + self.alpha * x_adv.grad.sign()
                eta = torch.clamp(x_adv - original, -self.epsilon, self.epsilon)
                x_adv = torch.clamp(original + eta, 0, 1)

        with torch.no_grad():
            orig_out = self.model(x).softmax(dim=1)
            adv_out = self.model(x_adv).softmax(dim=1)
            orig_pred = int(orig_out.argmax(dim=1).item())
            adv_pred = int(adv_out.argmax(dim=1).item())
            orig_conf = float(orig_out[0, label].item())
            adv_conf = float(adv_out[0, label].item())

        adv_np = x_adv.detach().squeeze(0).numpy()
        pert = (adv_np - image).astype(np.float64)

        return AdversarialImage(
            original=image,
            adversarial=adv_np,
            perturbation=pert,
            original_prediction=orig_pred,
            adversarial_prediction=adv_pred,
            original_confidence=orig_conf,
            adversarial_confidence=adv_conf,
            attack_name=f"PGD(e={self.epsilon})",
            l2_distance=float(np.sqrt(np.sum(pert**2))),
            linf_distance=float(np.max(np.abs(pert))),
            success=adv_pred != orig_pred,
        )


class CarliniWagnerL2:
    """CW-L2: minimal L2 perturbation attack (Carlini & Wagner 2016)."""

    def __init__(
        self,
        model: Any,
        confidence: float = 0.0,
        max_iter: int = 1000,
        lr: float = 0.01,
        binary_search_steps: int = 9,
    ) -> None:
        self.model = model
        self.confidence = confidence
        self.max_iter = max_iter
        self.lr = lr
        self.binary_search_steps = binary_search_steps

    def generate(self, image: np.ndarray, label: int) -> AdversarialImage:
        import torch

        x = torch.from_numpy(image).float().unsqueeze(0)

        self.model.eval()
        with torch.no_grad():
            orig_out = self.model(x).softmax(dim=1)
            orig_pred = int(orig_out.argmax(dim=1).item())
            orig_conf = float(orig_out[0, label].item())

        if orig_pred != label:
            return AdversarialImage(
                original=image,
                adversarial=image,
                perturbation=np.zeros_like(image),
                original_prediction=orig_pred,
                adversarial_prediction=orig_pred,
                original_confidence=orig_conf,
                adversarial_confidence=orig_conf,
                attack_name="CW-L2",
                l2_distance=0.0,
                linf_distance=0.0,
                success=False,
            )

        best_adv = image.copy()
        best_l2 = float("inf")
        c_low = 1e-4
        c_high = 1e1

        for _ in range(self.binary_search_steps):
            c = (c_low + c_high) / 2
            w = torch.zeros_like(x, requires_grad=True)
            optimizer = torch.optim.Adam([w], lr=self.lr)

            for _ in range(self.max_iter):
                optimizer.zero_grad()
                adv = 0.5 * (torch.tanh(w) + 1)

                l2_dist = torch.sum((adv - x) ** 2)
                output = self.model(adv)
                target_logit = output[0, label]
                other_logits = output[0, :].clone()
                other_logits[label] = -float("inf")
                best_other = other_logits.max()

                loss = l2_dist + c * torch.clamp(target_logit - best_other + self.confidence, min=0)

                if loss.requires_grad:
                    loss.backward()
                    optimizer.step()

            with torch.no_grad():
                adv_final = 0.5 * (torch.tanh(w) + 1)
                l2 = float(torch.sqrt(torch.sum((adv_final - x) ** 2)).item())
                adv_pred = int(self.model(adv_final).argmax(dim=1).item())

                if l2 < best_l2 and adv_pred != orig_pred:
                    best_l2 = l2
                    best_adv = adv_final.detach().squeeze(0).numpy()

            if adv_pred != orig_pred:
                c_high = c
            else:
                c_low = c

        adv_np = best_adv
        pert = (adv_np - image).astype(np.float64)

        with torch.no_grad():
            adv_out = self.model(torch.from_numpy(adv_np).float().unsqueeze(0)).softmax(dim=1)
            adv_pred_val = int(adv_out.argmax(dim=1).item())
            adv_conf = float(adv_out[0, label].item())

        return AdversarialImage(
            original=image,
            adversarial=adv_np,
            perturbation=pert,
            original_prediction=orig_pred,
            adversarial_prediction=adv_pred_val,
            original_confidence=orig_conf,
            adversarial_confidence=adv_conf,
            attack_name=f"CW-L2(c={c:.4f})",
            l2_distance=float(np.sqrt(np.sum(pert**2))),
            linf_distance=float(np.max(np.abs(pert))),
            success=adv_pred_val != orig_pred,
        )
