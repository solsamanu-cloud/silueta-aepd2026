"""Parseo del campo VHT MIMO Control (3 bytes) que precede al informe
comprimido de beamforming 802.11ac.

Fuentes (citadas también en el código):
  [STD]  IEEE 802.11ac-2013, §9.4.1.65 (formato del MIMO Control) y
         §9.4.1.66 (informe comprimido: orden de ángulos, Nsc, SNR).
  [D26]  arXiv:2312.03986 — apéndice "Order of angles in the BFR using
         compressed beamforming": orden y número de ángulos φ/ψ por
         geometría (Nr, Nc).
  [H23]  Haque et al., "Wi-BFI" (arXiv:2309.04408): bits por ángulo según
         codebook y tipo de realimentación (SU 4/2 y 6/4; MU 9/7).
  [WPC]  WiPiCap (sarulab-ou/WiPiCap, MIT, commit c877e3c): fórmula del
         número de ángulos por subportadora y tabla Nsc por (BW, Ng);
         usada como oráculo de referencia cruzada.

La VERIFICACIÓN CRÍTICA (requisito de la tarea): el número de bits que el
estándar predice para el cuerpo debe coincidir con la longitud real. Si no
cuadra, la interpretación es errónea y check_body_length lanza ValueError —
un desajuste silencioso produciría ángulos plausibles pero falsos.
"""

from dataclasses import dataclass

# Número de subportadoras reportadas por (chanwidth, grouping) [STD] §9.4.1.66
# Tabla correspondiente reproducida en [D26] y [WPC].
#   grouping: 0 -> Ng=1, 1 -> Ng=2, 2 -> Ng=4
NSC_TABLE = {
    (0, 0): 52,  (0, 1): 30,  (0, 2): 16,     # 20 MHz
    (1, 0): 108, (1, 1): 58,  (1, 2): 30,     # 40 MHz
    (2, 0): 234, (2, 1): 122, (2, 2): 62,    # 80 MHz
    (3, 0): 468, (3, 1): 244, (3, 2): 124,    # 160 MHz
}

# Bits por ángulo (phi, psi) para realimentación SU según codebook [H23].
BITS_SU = {0: (4, 2), 1: (6, 4)}
# Realimentación MU: phi 9 bits, psi 7 bits [H23].
BITS_MU = {0: (7, 5), 1: (9, 7)}


@dataclass(frozen=True)
class VhtMimoControl:
    """Campos del VHT MIMO Control [STD] §9.4.1.65."""
    nc: int               # columnas de V (flujos espaciales), índice+1
    nr: int               # filas de V (antenas receptoras), índice+1
    chanwidth: int        # 0=20, 1=40, 2=80, 3=160 MHz
    grouping: int         # 0=Ng1, 1=Ng2, 2=Ng4
    codebookinfo: int     # 0 o 1: fija bits por ángulo (SU)
    feedbacktype: int     # 0=SU, 1=MU
    remaining_segments: int
    first_segment: int
    sounding_token: int

    # --- derivados ------------------------------------------------------------
    @property
    def ng(self):
        return (1, 2, 4)[self.grouping]

    @property
    def bits_phi(self):
        return BITS_MU[self.codebookinfo][0] if self.feedbacktype == 1 else BITS_SU[self.codebookinfo][0]

    @property
    def bits_psi(self):
        return BITS_MU[self.codebookinfo][1] if self.feedbacktype == 1 else BITS_SU[self.codebookinfo][1]

    @property
    def n_angles_each(self):
        """Ángulos φ y ψ por subportadora (el mismo número de cada uno).

        Fórmula [WPC], coherente con el orden de ángulos de [D26]:
        total = min(Nc, Nr-1) * (2*(Nr-1) - min(Nc, Nr-1) + 1), mitad φ y
        mitad ψ. Verificado: 2x2 -> 1φ+1ψ; 2x1 -> 1φ+1ψ; 4x2 -> 5φ+5ψ.
        """
        m = min(self.nc, self.nr - 1)
        return m * (2 * (self.nr - 1) - m + 1) // 2

    @property
    def n_subcarriers(self):
        """Subportadoras reportadas según (BW, Ng) [STD]/[D26]/[WPC]."""
        return NSC_TABLE[(self.chanwidth, self.grouping)]

    @property
    def bits_per_subcarrier(self):
        return self.n_angles_each * (self.bits_phi + self.bits_psi)

    def expected_body_bytes(self):
        """Longitud teórica del cuerpo: 1 byte SNR por flujo (Nc) + ángulos
        de todas las subportadoras, redondeado al byte superior [STD]."""
        bits = 8 * self.nc + self.n_subcarriers * self.bits_per_subcarrier
        return (bits + 7) // 8

    def check_body_length(self, n_bytes):
        """Falla ruidosamente si la longitud real no es la teórica."""
        esperado = self.expected_body_bytes()
        if n_bytes != esperado:
            raise ValueError(
                f"longitud del cuerpo {n_bytes} B != teórica {esperado} B "
                f"(bw={self.chanwidth}, Ng={self.ng}, {self.nr}x{self.nc}, "
                f"cb={self.codebookinfo}, fb={'MU' if self.feedbacktype else 'SU'}). "
                "Interpretación errónea o cuerpo truncado: NO decodificar.")
        return True


def parse(raw3):
    """Parsea los 3 bytes del VHT MIMO Control (little endian) [STD] §9.4.1.65:
    bits 0-2 Nc, 3-5 Nr, 6-7 BW, 8-9 grouping, 10 codebook, 11 feedback type,
    12-14 remaining segments, 15 first segment, 16-17 reserved, 18-23 token.
    Orden de campos verificado contra la disección de tshark 3.4.16 sobre las
    capturas reales del proyecto (viab04/T1-T4)."""
    if len(raw3) != 3:
        raise ValueError(f"el MIMO Control son 3 bytes, llegan {len(raw3)}")
    v = raw3[0] | (raw3[1] << 8) | (raw3[2] << 16)
    return VhtMimoControl(
        nc=(v & 0x7) + 1,
        nr=((v >> 3) & 0x7) + 1,
        chanwidth=(v >> 6) & 0x3,
        grouping=(v >> 8) & 0x3,
        codebookinfo=(v >> 10) & 0x1,
        feedbacktype=(v >> 11) & 0x1,
        remaining_segments=(v >> 12) & 0x7,
        first_segment=(v >> 15) & 0x1,
        sounding_token=(v >> 18) & 0x3F,
    )
