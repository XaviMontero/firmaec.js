// STUB: pendiente de portar desde certificate/ec/argosdata (reemplazar este archivo completo)
import { Certificate } from '../../../x509/certificate.js';
import { DatosUsuario } from '../../datos-usuario.js';

export function getRootCertificate(_certificado: Certificate): Certificate | null {
  throw new Error('argosdata: no portado');
}

export function getDatosUsuario(_certificado: Certificate): DatosUsuario | null {
  throw new Error('argosdata: no portado');
}
