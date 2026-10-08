#!/usr/bin/env python3
"""09-dt-dependence.py — caracterización empírica de la relación entre la
distancia de informes BFI consecutivos y su intervalo temporal (dt).

Pregunta: ¿es la relación distancia ~ dt lineal? Si no lo es, la
normalización por división (distance/dt) introduce un sesgo dependiente de
la cadencia (y por tanto del patrón de tráfico). Alternativa evaluada:
restringir las comparaciones a pares con dt en una banda estrecha
(por defecto 0,05–0,3 s) y usar la distancia cruda.

Salida (results/presencia/):
  - dt-dependencia.png — dispersión distancia vs dt por serie (cliente
    principal), con mediana por deciles de dt y recta de ajuste lineal.
  - dt-dependencia.txt — por serie/cliente/métrica: Spearman(distancia, dt),
    R² del ajuste lineal, fracción de pares en banda, Spearman residual
    dentro de banda, y comparación del delta de Cliff T1 vs T2 con muestra
    completa y restringida a la banda.

Uso: 09-dt-dependence.py [etiqueta=pcap ...] (PCAP propios, fuera del repositorio)
"""

import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib import bfi_parser, presence  # noqa: E402

RESULTS = os.path.join(os.path.dirname(__file__), "..", "results", "presencia")
DT_MIN, DT_MAX = 0.05, 0.3
METRICAS = ("euclidean", "cosine")


def pares_crudos(seg, metrica):
    """(dt, distancia cruda) de todos los pares consecutivos comparables."""
    dts, dists = [], []
    bodies = seg["body"].to_numpy()
    ts = seg["ts"].to_numpy()
    for i in range(1, len(seg)):
        a, b = bodies[i - 1], bodies[i]
        if a.size != b.size or a.size == 0:
            continue
        dts.append(float(ts[i] - ts[i - 1]))
        dists.append(presence._distance(a, b, metrica))
    return np.array(dts), np.array(dists)


def cliffs_delta(x, y):
    x = np.sort(np.asarray(x, dtype=np.float64))
    y = np.asarray(y, dtype=np.float64)
    n, m = x.size, y.size
    greater = sum(n - np.searchsorted(x, v, side="right") for v in y)
    less = sum(np.searchsorted(x, v, side="left") for v in y)
    return float((greater - less) / (n * m))


def main():
    from scipy import stats
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    args = [a for a in sys.argv[1:] if "=" in a]
    if "--help" in sys.argv or not args:
        print(__doc__)
        print("Solo PCAP propios/autorizados. Los CSV públicos de psi no contienen el cuerpo binario.")
        return
    os.makedirs(RESULTS, exist_ok=True)

    datos = {}   # (etiqueta, metrica) -> (dts, dists) del cliente principal
    lineas = []
    for item in args:
        etq, _, pcap = item.partition("=")
        df, _ = bfi_parser.parse_pcap(pcap)
        segs = presence.segment_by_config(df)
        segs.sort(key=len, reverse=True)
        seg = segs[0]          # cliente principal (más informes)
        ta = seg["ta"].iloc[0]
        for metrica in METRICAS:
            dts, dists = pares_crudos(seg, metrica)
            datos[(etq, metrica)] = (dts, dists, ta)
            rho, p_rho = stats.spearmanr(dts, dists)
            pendiente, corte, r, _, _ = stats.linregress(dts, dists)
            banda = (dts >= DT_MIN) & (dts <= DT_MAX)
            rho_b = (stats.spearmanr(dts[banda], dists[banda])[0]
                     if banda.sum() > 10 else float("nan"))
            lineas.append(
                f"{etq} [{ta}] {metrica}: n={len(dts)} "
                f"spearman={rho:.3f} (p={p_rho:.1e}) "
                f"R2_lineal={r**2:.3f} pendiente={pendiente:.1f} "
                f"| en banda [{DT_MIN},{DT_MAX}]: {banda.sum()} pares "
                f"({100*banda.mean():.0f}%), spearman_residual={rho_b:.3f}")

    # Confusión por tráfico: T1 vs T2 con muestra completa y restringida
    for metrica in METRICAS:
        if ("T1", metrica) in datos and ("T2", metrica) in datos:
            d1, v1, _ = datos[("T1", metrica)]
            d2, v2, _ = datos[("T2", metrica)]
            d_full = cliffs_delta(v1, v2)
            b1 = (d1 >= DT_MIN) & (d1 <= DT_MAX)
            b2 = (d2 >= DT_MIN) & (d2 <= DT_MAX)
            if b1.sum() > 10 and b2.sum() > 10:
                d_band = cliffs_delta(v1[b1], v2[b2])
                lineas.append(
                    f"T1 vs T2 {metrica}: delta muestra completa = "
                    f"{d_full:.3f} | restringida a banda = {d_band:.3f} "
                    f"(n={b1.sum()} vs {b2.sum()})")
            else:
                lineas.append(
                    f"T1 vs T2 {metrica}: banda sin muestras suficientes "
                    f"({b1.sum()} vs {b2.sum()}) — con estos patrones la "
                    f"banda no es viable, hace falta cadencia comparable")

    # Figura: un panel por métrica, dispersión por serie + mediana por deciles
    fig, axes = plt.subplots(1, len(METRICAS), figsize=(7 * len(METRICAS), 5))
    if len(METRICAS) == 1:
        axes = [axes]
    for ax, metrica in zip(axes, METRICAS):
        for etq in sorted({e for e, m in datos if m == metrica}):
            dts, dists, ta = datos[(etq, metrica)]
            ax.scatter(dts, dists, s=3, alpha=0.25, label=etq)
            # mediana por deciles de dt
            qs = np.quantile(dts, np.linspace(0, 0.98, 12))
            xm, ym = [], []
            for lo, hi in zip(qs[:-1], qs[1:]):
                m = (dts >= lo) & (dts < hi)
                if m.sum() >= 5:
                    xm.append(np.median(dts[m]))
                    ym.append(np.median(dists[m]))
            ax.plot(xm, ym, linewidth=1.6)
        ax.axvspan(DT_MIN, DT_MAX, color="green", alpha=0.08,
                   label=f"banda {DT_MIN}-{DT_MAX} s")
        ax.set_xscale("log")
        ax.set_xlabel("dt (s, escala log)")
        ax.set_ylabel(f"distancia {metrica} (cruda)")
        ax.set_title(f"distancia vs dt — {metrica}")
        ax.legend(fontsize=8, markerscale=3)
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "dt-dependencia.png"), dpi=120)

    informe = "\n".join(lineas) + "\n"
    with open(os.path.join(RESULTS, "dt-dependencia.txt"), "w") as fh:
        fh.write(informe)
    print(informe)
    print(f"figura: {os.path.join(RESULTS, 'dt-dependencia.png')}")


if __name__ == "__main__":
    main()
