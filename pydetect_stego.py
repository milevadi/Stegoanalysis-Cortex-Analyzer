#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer

import numpy as np
from PIL import Image


class StegoAnalyzer(Analyzer):
    """This is a minimal analyzer that just does nothing other than returning an empty result. It can be used as
    skeleton when creating new analyzers."""

    def __init__(self):
        """Initialization of the class. Here normally all parameters are read using `self.get_param`
        (or `self.getParam`)"""
        Analyzer.__init__(self)

    def check(self, image_path):

        result = []

        # Abrir la imagen
        img = Image.open(image_path)
        pixels = np.array(img)

        # Detección de LSB
        altered_pixels_lsb = 0
        for pixel in pixels:
            for color_component in pixel:
                for bit in range(8):
                    if ((color_component & (1 << bit)) != 0).all():
                        altered_pixels_lsb += 1

        # Detección de EOF
        end_of_file_marker = b'\xFF\xD9'  # Marcador EOF en JPEG
        image_data = open(image_path, 'rb').read()
        if end_of_file_marker in image_data:
            altered_eof = True
        else:
            altered_eof = False

        # Mostrar resultados
        if altered_pixels_lsb > 0:
            result.append("Se encontraron cambios en los bits LSB. Posible esteganografía LSB.")
        else:
            result.append("No se encontraron cambios en los bits LSB.")

        if altered_eof:
            result.append("Se encontró el marcador EOF al final del archivo. Posible esteganografía EOF.")
        else:
            result.append("No se encontró el marcador EOF al final del archivo.")
    
        return result
    
    def summary(self, raw):
        taxonomies = []
        namespace = "Stegoanalysis"
        predicate = "Match"

        if raw["results"]:
            value = "{}".format(raw["results"])
            level = "malicious"
        else:
            value = "No matches"
            level = "safe"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):

        Analyzer.run(self)

        if self.data_type == 'file':
            self.report({'results': self.check(self.get_param('file'))})
        else:
            self.error('Wrong data type: jpg')


if __name__ == "__main__":
    """This is necessary, because it is called from the CLI."""
    StegoAnalyzer().run()
