"""Parseo del campo HE MIMO Control (5 bytes) que precede al informe
comprimido de beamforming 802.11ax (informe "HE Compressed Beamforming
And CQI").

Formato (verificado byte a byte contra tramas reales del ALFA, ver
docs/HALLAZGO-HE-BFI.md):
  - Campo de 40 bits leído little-endian desde 5 bytes.
  - Nc Index (3 bits), Nr Index (3 bits), Channel Width (2 bits),
    Grouping (1 bit), Codebook Info (1 bit), Feedback Type (2 bits),
    Remaining Feedback Segments (3 bits), First Feedback Segment (1 bit),
    RU Start Index (7 bits), RU End Index (7 bits), Sounding Dialog
    Token Number (6 bits), Reserved (4 bits).
  - Mapeos DIFERENTES a VHT (802.11ac):
      * Grouping es 1 bit y está INVERTIDO: 0 -> Ng=4, 1 -> Ng=1.
        En VHT 0->Ng=1. Confirmado empíricamente: la tramas del Xiaomi
        llevan grouping=0 y reportan CADA subportadora de datos (250 en
        80 MHz), paso 4 en SCIDX.
      * El ancho de canal usa la FFT HE: 20/40/80/160 MHz -> 256/512/
        1024/2048 tonos. En 80 MHz (1024 FFT) las subportadoras de datos
        reportadas a Ng=4 son 250, SCIDX +-(4..500) excluyendo DC.
  - Bits por ángulo: SU codebook 1 -> phi 6 / psi 4; SU codebook 0 ->
    phi 4 / psi 2 (igual que VHT). Confirmado: max phi=50, max psi=13
    en las tramas reales. MU -> 4/2 por convenio del estándar (pendiente
    de verificar con captura real).

La VERIFICACIÓN CRÍTICA es la misma que en VHT: expected_body_bytes()
debe cuadrar con la longitud real del cuerpo; si no, check_body_length
lanza ValueError y NO se decodifica (nunca ángulos plausibles pero falsos).
"""

from dataclasses import dataclass

# Bits por ángulo (phi, psi) para realimentación SU según codebook.
BITS_SU = {0: (4, 2), 1: (6, 4)}
# MU: convenio del estándar (codebook 0). Pendiente de verificar en vivo.
BITS_MU = (4, 2)

# Número de subportadoras reportadas (bw, grouping) para informe de banda
# completa. Modelo: FFT = 256*2^bw tonos; por lado se reportan
# (FFT/2 - GUARD)/Ng, con GUARD=12 derivado de la observación en 80 MHz
# (SCIDX hasta +-500 = +-512 menos 12 de guarda). Solo (2,0)=250 está
# verificado EMPÍRICAMENTE contra tramas reales del Xiaomi; el resto es
# modelo sujeto a la verificación de longitud (check_body_length) cuando
# aparezcan clientes con otras configuraciones.
HE_NSC_TABLE = {
    (0, 0): 58,   # 20 MHz, Ng=4
    (0, 1): 232,  # 20 MHz, Ng=1
    (1, 0): 122,  # 40 MHz, Ng=4
    (1, 1): 488,  # 40 MHz, Ng=1
    (2, 0): 250,  # 80 MHz, Ng=4  <- VERIFICADO con tramas reales
    (2, 1): 1000, # 80 MHz, Ng=1
    (3, 0): 506,  # 160 MHz, Ng=4
    (3, 1): 2024, # 160 MHz, Ng=1
}


@dataclass(frozen=True)
class HeMimoControl:
    """Campos del HE MIMO Control (802.11ax)."""
    nc: int               # columnas de V (flujos espaciales), índice+1
    nr: int               # filas de V (antenas receptoras), índice+1
    chanwidth: int        # 0=20, 1=40, 2=80, 3=160 MHz
    grouping: int         # 0=Ng4, 1=Ng1  (INVERTIDO respecto a VHT)
    codebookinfo: int     # 0 o 1: fija bits por ángulo (SU)
    feedbacktype: int     # 0=SU, 1=MU
    remaining_segments: int
    first_segment: int
    ru_start: int
    ru_end: int
    sounding_token: int

    @property
    def ng(self):
        return (4, 1)[self.grouping]

    @property
    def bits_phi(self):
        if self.feedbacktype == 1:
            return BITS_MU[0]
        return BITS_SU[self.codebookinfo][0]

    @property
    def bits_psi(self):
        if self.feedbacktype == 1:
            return BITS_MU[1]
        return BITS_SU[self.codebookinfo][1]

    @property
    def n_angles_each(self):
        """Ángulos φ y ψ por subportadora (el mismo número de cada uno).

        Misma fórmula que VHT: total = min(Nc, Nr-1) * (2*(Nr-1) -
        min(Nc, Nr-1) + 1), mitad φ y mitad ψ. Verificado 2x2 -> 1φ+1ψ.
        """
        m = min(self.nc, self.nr - 1)
        return m * (2 * (self.nr - 1) - m + 1) // 2

    @property
    def n_subcarriers(self):
        return HE_NSC_TABLE[(self.chanwidth, self.grouping)]

    @property
    def bits_per_subcarrier(self):
        return self.n_angles_each * (self.bits_phi + self.bits_psi)

    def expected_body_bytes(self):
        """Longitud teórica del cuerpo (SNR + matriz), sin contar los
        5 bytes del HE MIMO Control: 1 byte SNR por flujo (Nc) + ángulos
        de todas las subportadoras, redondeado al byte superior."""
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


def parse(raw5):
    """Parsea los 5 bytes del HE MIMO Control (little endian).

    Layout de 40 bits verificado contra la disección de tshark 4.6.7 y el
    bytecode real: Nc 3b, Nr 3b, BW 2b, grouping 1b, codebook 1b, feedback
    type 2b, remaining 3b, first 1b, RU start 7b, RU end 7b, token 6b,
    reserved 4b.
    """
    if len(raw5) != 5:
        raise ValueError(f"el HE MIMO Control son 5 bytes, llegan {len(raw5)}")
    v = (raw5[0] | (raw5[1] << 8) | (raw5[2] << 16)
         | (raw5[3] << 24) | (raw5[4] << 32))
    return HeMimoControl(
        nc=(v & 0x7) + 1,
        nr=((v >> 3) & 0x7) + 1,
        chanwidth=(v >> 6) & 0x3,
        grouping=(v >> 8) & 0x1,
        codebookinfo=(v >> 9) & 0x1,
        feedbacktype=(v >> 10) & 0x3,
        remaining_segments=(v >> 12) & 0x7,
        first_segment=(v >> 15) & 0x1,
        ru_start=(v >> 16) & 0x7F,
        ru_end=(v >> 23) & 0x7F,
        sounding_token=(v >> 30) & 0x3F,
    )
