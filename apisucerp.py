# -------Lista de lisbrerias y Modulos
try:

    # libreria de flask
    from flask import Blueprint
    from flask import request
    from pydal.objects import Table


    # libreria json
    import json

    from datetime import datetime

    import os

    # Clase de configuracion
    from app_Config.config import ConfigurarAplicacion

    # Gestion Registros
    from app_Abstract.gestionRegistros import GestionRegistros

    # clase de atributos
    from app_Abstract.atributosAbstract import AtributosSucerp

    # Funciones de token
    from app_Token.function_jwt import write_token, validate_token


except Exception as e:
    print(f'Falta algun modulo {e}')


# generamos Instancia de ConfigurarAplicacion
api = ConfigurarAplicacion()

# recuperamos el ambiente
db = GestionRegistros(ambiente=api.ENV_GX)

idcontribuyente = ''

automotor_api = Blueprint('automotor_api', __name__)

tablalog = db.__getattribute__(api.LISTA_TABLAS['TABLA_API_LOG']['objeto'])

tablaApiAumoso = db.__getattribute__(api.LISTA_TABLAS['TABLA_API_AUMOSO']['objeto'])

tablaApiRegistro = db.__getattribute__(api.LISTA_TABLAS['TABLA_API_REGISTROS']['objeto'])

tablaApiToken = db.__getattribute__(api.LISTA_TABLAS['TABLA_API_TOKEN']['objeto'])

tablaApiTareas = db.__getattribute__(api.LISTA_TABLAS['TABLA_API_TAREAS']['objeto'])

tablaApiEstadosTareas = db.__getattribute__(api.LISTA_TABLAS['TABLA_API_ESTADOS_TAREAS']['objeto'])

tablaApiTokenUser = db.__getattribute__(api.LISTA_TABLAS['TABLA_API_TOKEN_USER']['objeto'])

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# control del Api de Conexion
def controlApiConexion(**data):

    try:

        #---------control idusuario y password----------------------------------
        print(data)
        if  ('idusuario' in data) and ('password' in data):
            # ---------control idusurio y password--------------------------------
            if not isinstance(data['idusuario'], str) \
                    or not data['idusuario'].isdigit(): return False
            if not isinstance(data['password'], str): return False
            return True
        #---------control idusuario y password no encontrado------------
        else:
            return False

    except Exception as e:
        print(f'Error en el Control de Api de conexion - {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# control del Api de Deuda
def controlApiDeuda(**data):

    try:

        ctl01 = ('identificador' in data) \
                and  ('id_registro' in data['identificador']) \
                and ('id_usuario' in data['identificador'])

        ctl02 = ('dominio' in data) \
                and ('dominio_viejo' in data)

        ctl03 = ('tipo_vehiculo' in data) \
                and   ('automovil' in data['tipo_vehiculo']) \
                and ('moto' in data['tipo_vehiculo'])

        # -----------------Control Json
        if ctl01 and ctl02 and ctl03:
            if not isinstance(data['identificador']['id_registro'], int): return False
            if not isinstance(data['identificador']['id_usuario'], int): return False
            if not isinstance(data['dominio'], str): return False
            if not isinstance(data['dominio_viejo'], str): return False
            if not isinstance(data['tipo_vehiculo']['automovil'], str): return False
            if not isinstance(data['tipo_vehiculo']['moto'], str): return False
            return True
        # --------------Por Error
        else:

            return False

    except Exception as e:
        print(f'Error en el Control de Api de Deuda - {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# control del Api de Pago de Deuda
def controlApiPagoDeuda(**data):

    try:


        ctl01 = ('fecha_pago' in data['pago']) \
                and ('registro' in data['pago'])

        ctl02 = ('tramite' in data['pago']) \
                and ('formulario' in data['pago']) \
                and ('dominio' in data['pago']) \
                and ('dominio_viejo' in data['pago']) \
                and ('cuotas' in data['pago'])


        if not ctl01: return False
        if not ctl02: return False
        if not isinstance(data['pago']['tramite'], int): False
        if not isinstance(data['pago']['formulario'], int): False
        if not isinstance(data['pago']['dominio'], str): False
        if not isinstance(data['pago']['dominio_viejo'], str): False
        if not isinstance(data['pago']['fecha_pago'], str): return False
        if not isinstance(data['pago']['registro']['id'], str): return False
        if not isinstance(data['pago']['registro']['nombre'], str): return False
        if not isinstance(data['pago']['cuotas'], list): return False


        for x in data['pago']['cuotas']:
            if  not ('apiaumosoid' in x) \
                    or not (isinstance(x['apiaumosoid'], int)): return False
            if not ('codigo_forma_pago' in x) \
                    or not (isinstance(x['codigo_forma_pago'], int)): return False
            if not ('codigo_moneda' in x) \
                    or not (isinstance(x['codigo_moneda'], int)): return False
        return True

    except Exception as e:
        print(f'Error en el Control de Api Pago de Deuda - {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# obtengo el estado que le corresponde
def obtengoIdContribuyente(db, key):

    try:

        # consultamos la tabla APIAUMOSO
        rtn = db.get_Rows(tablaApiAumoso, key)

        return rtn[0]['idcontrib']

    except Exception as e:
        print(f'Error - Obtengo_Apiaumoso {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# obtengo el estado que le corresponde
def obtengoApiAumoso(db, id):

    try:

        where = {
            'fieldnumber': [1, ],
            'field': [id, ],
            'struct_query': ['fld', ],
            'op': ['EQ', ],
            'order': False,
            'pageno': False,
            'indexpageno': False,
            'seleccion': False,
            'wrkrecords': False
        }
        # consultamos la tabla APIAUMOSO
        return db.get_rowsWhereWrk(tablaApiAumoso, **where)


    except Exception as e:
        print(f'Error - Obtengo_Apiaumoso {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# obtengo los datos del registro
def obtengoApiRegistros(db, **data):

    try:


        where = {
            'fieldnumber': [2, ],
            'field': [ int(data['id']), ],
            'struct_query': ['fld', ],
            'op': ['EQ', ],
            'order': False,
            'pageno': False,
            'indexpageno': False,
            'seleccion': False,
            'wrkrecords': False
        }

        # consulta APIREGISTRO
        return db.get_rowsWhereWrk(tablaApiRegistro, **where)

    except Exception as e:
        print(f'Error - Obtengo_Apiaumoso {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# obtengo el estado que le corresponde
def actualizaApiToken(db, id):

    try:

        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # cierro la vigencia del token
        key = id
        campos_apitoken = dict()

        campos_apitoken = {
            "apiestadotareasid": 2,
            "tokenfintransaccion": True,
        }

        # consultamos APITOKEN
        return db.upd_Dal(tablaApiToken, key, **campos_apitoken)


    except Exception as e:
        print(f'Error - Obtengo_Estado {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# obtengo el estado que le corresponde
def obtengoApiToken(db, token):

    try:

        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # Arma el query de busqueda para leer APITOKEN
        where = {
            'fieldnumber': [1, ],
            'field': [token, ],
            'struct_query': ['fld', ],
            'op': ['EQ', ],
            'order': False,
            'pageno': False,
            'indexpageno': False,
            'seleccion': False,
            'wrkrecords': False
        }

        # consulta APITOKEN
        return db.get_rowsWhereWrk(tablaApiToken, **where)

    except Exception as e:
        print(f'Error - Obtengo_Estado {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# obtengo el estado que le corresponde
def obtengoEstado(estadoInicial, tarea):

    try:

        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # Arma el query de busqueda para leer APITAREAS
        where = {
            'fieldnumber': [1, ],
            'field': [tarea, ],
            'struct_query': ['fld', ],
            'op': ['EQ', ],
            'order': False, 'pageno': False, 'indexpageno': False, 'seleccion': False,
            'wrkrecords': False
        }

        # consulta APITAREAS
        rtn, error = db.get_rowsWhereWrk(tablaApiTareas, **where)


        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # Arma el query de busqueda para leer APIESTADOSTAREAS
        where = {
            'fieldnumber': [1, 2],
            'field': [estadoInicial, rtn[0]['apitareasid'], ],
            'struct_query': ['fld', '&', ],
            'op': ['EQ', 'EQ', ],
            'order': False, 'pageno': False, 'indexpageno': False, 'seleccion': False,
            'wrkrecords': False
        }

        # Read APIESTADOSTAREAS
        rtn, error = db.get_rowsWhereWrk(tablaApiEstadosTareas, **where)

        return rtn[0]['apiestadosnewid']

    except Exception as e:
        print(f'Error - Obtengo_Estado {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# Generamos el Log del sistema
def genera_log(db, contrib, **data):

    try:

        # cargamos los campos del registros de la tabla log
        campos_log = {
            "apilogerror": json.dumps(data),
            "apilogtimestamp": datetime.now(),
            "apilogidcontrib": contrib
        }

        # garbamos APILOG
        retorno = db.add_Dal(tablalog, **campos_log)
        return retorno

    except Exception as e:
        print(f'Error genero Log {e} ')
    except EOFError as b:
        print(f'Erroxxr {b}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# VERIFICAMOS LA CONEXION DE DATOS Y RECUPERAMOS LOS DATOS
def verify_data_conexion(db, **data):
    """
    Verificamos lo siguiente:
        Si el  idusuario es el que se encuentra en la configuracion de la aplicacion
        Si la password es la que se encuentra en la configuracion de la aplicacion

    Verificamos si el idregistro existe en la tabla APIREGISTROS
    Verificamos si el idusuario del idregistro recibido en el link existe en la tabla APITOKENUSER
    Verificamos si el idusuario tiene asignado el idregistro

    :param data: Es un dict con el idregistro, idusuario
    :return: Un False o True y un dict de Error
    """

    try:

        # verifica usuario
        if data['jsonidusuario'] == api.SUCERP_USER:

            # verifica la password
            if data['password'] == api.SUCERP_PASS:


                # verificamos si el token ya existe
                if 'identificador' in data:

                    where = {
                        'fieldnumber': [1, ],
                        'field': [data['identificador']['token'], ],
                        'struct_query': ['fld', ],
                        'op': ['EQ', ],
                        'order': False,
                        'pageno': False,
                        'indexpageno': False,
                        'seleccion': False,
                        'wrkrecords': False
                    }

                    # read APITOKEN
                    rtn, error = db.get_rowsWhereWrk(tablaApiToken, **where)

                    # hay registros verificamos si la transaccion ha sido cerrada
                    if len(rtn) > 0 and rtn[0]['tokenfintransaccion'] == True:
                        error = api.ERROR_413
                        return False, error

                # recuperamos registros del idregistro recibido desde el api
                if 'identificador' in data:
                    registros, error = db.get_Rows(tablaApiRegistro, data['identificador']['id_registro'])
                else:
                    registros, error = db.get_Rows(tablaApiRegistro, data['id_registro'])


                # si no hay registros retornamos el rtn = False, error = descripcion del Error
                if len(registros) == 0:
                    error = api.ERROR_401
                    return False, error

                # recuperamos los registros del idusuario recibido desde el api
                if 'identificador' in data:
                    registros, error = db.get_Rows(tablaApiTokenUser, data['identificador']['id_usuario'])
                else:
                    registros, error = db.get_Rows(tablaApiTokenUser, data['id_usuario'])

                # si no hay registros retornamos el rtn = False, error = descripcion del Error
                if len(registros) == 0:
                    error = api.ERROR_402
                    return False, error

                # verificamos si el usuario tiene asignado el registro
                contenido = registros

                # si el idregistro existe en la tabla
                if contenido['apiregistrosid'] == data['id_registro']:
                    error = api.ERROR_000
                    return True, error

            # si la password no es la correcta en el Json recibido
            else:
                error = api.ERROR_404
                return False, error

        # si el usuario no es el correcto en el Json recibido
        else:
            error = api.ERROR_403
            return False, error

    except Exception as e:
        print(f'Error - verify_data_conexion {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# CONTROLAMOS LA CONEXION ANTE EL PEDIDO DE SUCERP
def verifcaconexion(db, **data):
    """
    puede venir
            id_usuario, id_registros


    Verificamos lo siguiente:
        Si existe el idregistro en la tabla APIREGISTRO
        Si existe el idusuario en la tabla APITOKENUSER
        Si el idregistro esta asignado al registros

    Si no hubo error  generamos un token y  registramos el token
    en la tabla  APITOKEN

    :param data: Es un dict con el idregistro, idusuario
    :return: retornamos un json
    """

    try:

        # verifica los datos de conexion
        # rtn = (True o False)
        # error la descripcion si rtn es False

        # ----------------verificamos la conexion
        rtn, error = verify_data_conexion(db, **data)

        # si hay error en la verificacion de la conexion
        if not rtn:
            data['error'] = error
            rtnlog = genera_log(db, '', **data)
            return json.dumps(data)


        # si no hay error en la verificacion de la conexion
        else:

            # Armamos el Token
            campos = dict()

            # Obtengo el time stamp
            data['pedido'] = str(datetime.now())

            # Armamos la respuesta
            respuesta = {
                "identificador": {
                    "id_registro": data['id_registro'],
                    "id_usuario": data['id_usuario'],
                    "token": write_token(**data).decode('utf-8')
                },
                "error": error
            }

            # llenamos los campos para agregar la tabla APITOKEN
            campos['tokenvalor'] = respuesta['identificador']['token']
            campos['apiuserid'] = data['id_usuario']
            campos['tokentimestamp'] = datetime.now()
            campos['apiregistrosid'] = data['id_registro']
            campos['apiestadotareasid'] = 1
            campos['tokenconectar'] = True
            campos['tokeniniciotransaccion'] = True
            campos['tokenfontransaccion'] = False

            # grabamos el nuevo token
            rtn = set_conexion(db, **campos)

            # Informamos al Log
            rtnlog = genera_log(db, '', **respuesta)

            # retornamos un json
            return json.dumps(respuesta)

    except Exception as e:
        print(f'Error - verifcaconexion {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# OBTENEMOS LA DEUDA DEL AUTOMOTOR PEDIDA POR SUCERP
def get_deuda(db, **data):

    """
    Verificamos los datos de conexion
    Verificamos la validez del token
    Obtenemos la deuda del Dominio su paKey (store Procedure)
    Obtenemos registros del AUMOSO con un paKey

    :param data: Es un dict con el json recibido
    :return: json
    """

    try:

        # Armamos el mensaje de retorno
        deuda = dict()
        deuda['identificador'] = dict()
        deuda['identificador']['id_registro'] = data['identificador']['id_registro']
        deuda['identificador']['id_usuario'] = data['identificador']['id_usuario']
        deuda['identificador']['token'] = data['identificador']['token']
        deuda['deuda'] = list()
        deuda['error'] = dict()

        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # verifica los datos de conexion
        # rtn = (True o False)
        # error la descripcion si rtn es False
        datos = dict()

        datos['id_registro'] = data['identificador']['id_registro']
        datos['jsonidusuario'] = api.SUCERP_USER
        datos['id_usuario'] = data['identificador']['id_usuario']
        datos['password'] = api.SUCERP_PASS
        datos['identificador'] = data['identificador']

        # ---------------verifica los datos de conexion-----------------------------------------
        rtn, error = verify_data_conexion(db, **datos)

        # si hay error en la verificacion de conexion
        # retornamos el mensaje
        if not rtn:
            data['error'] = error
            rtnlog = genera_log(db, '', **data)
            return json.dumps(data)


        # ------Verificamos si el token esta habilitado--------------------------------------
        rtn, error = validate_token(data['identificador']['token'], output=True)

        # si hay error al verificar si el token esta habilitado
        if not rtn:
            data['error'] = error
            rtnlog = genera_log(db, '', **data)
            return json.dumps(data)

        # -----------------------Llamar al store Procedure-------------------------------------------
        parametros = list()

        dom_nuevo = str(data['dominio'])
        parametros.append(f"0        {dom_nuevo}")
        parametros.append(str(data['tipo_vehiculo']['automovil']))
        parametros.append(str(data['tipo_vehiculo']['moto']))

        # Convertimos la lista en tupla
        parametros = tuple(parametros)

        # Armamos  la  sentencia SQL del al Store Procedure
        sql = "{CALL APIAUTOMO ( ?, ?, ? ) }"
        print(f'Los parametros son: {parametros}')
        # -----------Recuperamos el Pakey--------------------------------------------------------
        rtn = db.run_comando(sql, *parametros)

        # controla si hay error al ejecutar el store procedure
        if not 'error' in rtn:

            # Si no tiene deuda el contribuyente
            if len(rtn) == 0:

                # --------------------obtengo el API TOKEN----------------------------------------
                rtn, error = obtengoApiToken(db, data['identificador']['token'])

                # si hay error en la lectura del APITOKEN
                if not rtn:
                    data['error'] = api.ERROR_409
                    rtnlog = genera_log(db, '', **data)
                    return json.dumps(data)

                # si no hay error en la lectura del APITOKEN
                else:

                    # ------------actualiza el APITOKEN cierra la transaccion----------------
                    rtn = actualizaApiToken(db, rtn[0]['tokenapiid'])

                    # Si la actualizacion es correcta
                    if rtn == False:
                        data['error'] = api.ERROR_411
                        rtnlog = genera_log(db, '', **data)
                        return json.dumps(data)

                # El contribuyente no tiene deuda
                data['error'] = api.ERROR_408
                # Informamos al Log
                rtnlog = genera_log(db, '', **data)
                return json.dumps(data)

            # -------------Recupera la deuda del Contribuyente------------------------
            pedido = dict()
            pedido['idpakey'] = rtn[0][0]
            pedido['reservado'] = None

            # --------------recuperamos el Apiaumoso------------------------------------------
            rtn, error = obtengoApiAumoso(db, rtn[0][0])

            # si hay error en la busqueda del Apiaumoso
            if not rtn:
                data['error'] = api.ERROR_410
                rtnlog = genera_log(db, '', **data)
                return json.dumps(data)

            # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
            # Si no hay error en la busqueda del Apiaumoso cargamos la deuda
            else:

                # armamos el json de respuesta
                deudalista = list()

                # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                # Recorre el cursor
                for l in rtn:

                    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                    # Solo lo que no esta cancelada
                    if l['cuotacancelada'] != 'S':
                        detalle = dict()
                        detalle['anio'] = l['samaaocuo']
                        detalle['cuota'] = l['samcuota']
                        detalle['tipo_cuota'] = '1'
                        detalle['fecha_bonificacion'] = str(l['samfevtbon'])

                        if detalle['fecha_bonificacion'] == '0001-01-01': detalle['fecha_bonificacion'] = ''

                        detalle['importe_cuota'] = str(l['samimporte'])
                        detalle['fecha_vencimiento'] = str(l['samfecvto'])
                        detalle['importe'] = str(l['samimporte'])
                        detalle['fecha_proceso'] = str(l['samfeccal'])
                        detalle['punitorios'] = str(l['samintpuni'])
                        detalle['observaciones'] = ''
                        detalle['reservado'] = l['samcodbarr']
                        detalle['apiaumosoid'] = l['aumosoid']
                        deudalista.append(detalle)

                # asignamos la deuda
                deuda['deuda'] = deudalista
                deuda['error'] = api.ERROR_000
                rtnlog = genera_log(db, '', **deuda)
                return  json.dumps(deuda)

        # Error en el store Procedure
        # retornamos el mensaje
        else:

            # --------------------obtengo el API TOKEN----------------------------------------
            rtn, error = obtengoApiToken(db, data['identificador']['token'])

            # si hay error en la lectura del APITOKEN
            if not rtn:
                data['error'] = api.ERROR_409
                rtnlog = genera_log(db, '', **data)
                return json.dumps(data)

            # si no hay error en la lectura del APITOKEN
            else:

                # ------------actualiza el APITOKEN cierra la transaccion----------------
                rtn = actualizaApiToken(db, rtn[0]['tokenapiid'])

                # Si la actualizacion es correcta
                if rtn == False:
                    error = api.ERROR_409
                    rtnlog = genera_log(db, '', **data)
                    return json.dumps(data)


            data['error'] = api.ERROR_405
            rtnlog = genera_log(db, '', **data)
            return json.dumps(data)


    except Exception as e:
        print(f'Error - modulo get_deuda {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# GENERAMOS UN NUEVO REGISTRO DE PEDIDO DE CONEXION ENVIADO POR SUCERP
def set_conexion(db, **data):
    """
    Genera un nuevo registro en la tabla APITOKEN
    :param data: dict con los campos generar el registro
    :return: los registros de APITOKEN
    """
    try:


        # Generamos un nuevo Registro en el APITOKEN
        rtn = db.add_Dal(tablaApiToken, **data)

        # Si no es True
        if rtn != True:
            error = api.ERROR_406
            respuesta = dict()
            respuesta['identificador'] = dict()
            respuesta['identificador']['id_registro'] = data['identificador']['id_registro']
            respuesta['identificador']['id_usuario'] = data['identificador']['id_usuario']
            respuesta['identificador']['token'] = data['identificador']['token']
            respuesta['error'] = dict()
            respuesta['error']['code'] = error['code']
            respuesta['error']['descripcion'] = f"{error['descripcion']} id = {key} "

            # genera un registro en el log
            rtnlog = genera_log(db, '', **respuesta)

            respuesta['error']['descripcion'] = f"{error['descripcion']} id = {key}-{db.ultimoid} "

            return json.dumps(respuesta)

        return True

    except Exception as e:
        print(f'Error - set_conexion {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# ASIGNAMOS EL PAGO ENVIADO POR SUCERP
def set_pago(db, **data):
    """
    :param data:  dict del json recibido
    :return: retornamos un json con la respuesta
    """

    try:

        # Cuotas a pagar
        pago_deuda = list()
        pago_deuda = data['pago']['cuotas']

        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # verifica los datos de conexion
        # rtn = (True o False)
        # error la descripcion si rtn es False
        datos = dict()
        datos['jsonidusuario'] = api.SUCERP_USER
        datos['id_registro'] = int(data['identificador']['id_registro'])
        datos['id_usuario'] = int(data['identificador']['id_usuario'])
        datos['password'] = api.SUCERP_PASS


        # ---------verificamos la conexion---------------------------------------------------
        rtn, error = verify_data_conexion(db, **datos)

        # si hay error en la verificacion de la conexion
        if not rtn:
            data['error'] = error
            rtnlog = genera_log(db, '', **data)
            return json.dumps(data)

        # ------------Verificamos si el token esta habilitado-----------------------------
        rtn, error = validate_token(data['identificador']['token'], output=True)

        # si hay error en la verificacion sie l token esta habilitado
        if not rtn:
            data['error'] = error
            rtnlog = genera_log(db, '', **data)
            return json.dumps(data)

        # -------------------obtengo el APIREGISTROS-----------------------------------
        rtn, error = obtengoApiRegistros(db, **data['pago']["registro"])

        # si hay error en la lectura del APIREGISTROS
        if not rtn:
            data['error'] = api.ERROR_414
            rtnlog = genera_log(db, '', **data)
            return json.dumps(data)

        # --------------------obtengo el API TOKEN----------------------------------------
        rtn, error =  obtengoApiToken( db,  data["identificador"]["token"] )

        # si hay error en la lectura del APITOKEN
        if not rtn:
            data['error'] = api.ERROR_409
            rtnlog = genera_log(db, '', **data)
            return json.dumps(data)

        # si no hay error en la lectura del APITOKEN
        tokenid = rtn[0]['tokenapiid']

        # Procesamos los pagos
        rec = list()
        transaccion = dict()

        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # Actualizamos la tabla APIAUMOSO
        for p in pago_deuda:

            # campos del APIAUMOSO
            # obtengo idaumoso desde el
            campos_aumoso = dict()

            # ---------obtengo el id contribuyente del APIAUMOSO----------------
            idcontribuyente = ''
            idcontribuyente = obtengoIdContribuyente(db, int(p['apiaumosoid']))

            key = int(p['apiaumosoid'])

            campos_aumoso = {
                "tokenapiid": tokenid,
                "cuotacancelada": 'S',
                "codigotipotramite": int(data['pago']['tramite']),
                "tipoformulario": int(data['pago']['formulario']),
            }

            # actualizamos APIAUMOSO
            rtn = db.upd_Dal(tablaApiAumoso, key, **campos_aumoso)

            # -----------------Si la operacion na ha sido exitosa---------------------------------
            if rtn != True:

                # ------------actualiza el APITOKEN cierra la transaccion----------------
                rtn = actualizaApiToken(db, tokenid)

                # Si la actualizacion es correcta
                if rtn == False:
                    data['error'] = api.ERROR_411
                    rtnlog = genera_log(db, '', **data)
                    return json.dumps(data)


                error = api.ERROR_406
                respuesta = dict()
                respuesta['identificador'] = dict()
                respuesta['identificador']['id_registro'] = data['identificador']['id_registro']
                respuesta['identificador']['id_usuario'] = data['identificador']['id_usuario']
                respuesta['identificador']['token'] = data['identificador']['token']
                respuesta['error'] = dict()
                respuesta['error']['code'] = error['code']
                respuesta['error']['descripcion'] = f"{error['descripcion']} id = {key} "
                respuesta['error']['descripcion'] = f"{error['descripcion']} id = {key}-{db.ultimoid} "

                # genera un registro en el log
                rtnlog = genera_log(db, '', **respuesta)

                return json.dumps(respuesta)

        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # cierro la vigencia del token

        # ------------actualiza el APITOKEN cierra la transaccion----------------
        rtn = actualizaApiToken(db, tokenid)

        # Si la actualizacion es correcta
        if rtn == False:
            data['error'] = api.ERROR_411
            rtnlog = genera_log(db, '', **data)
            return json.dumps(data)

        error = api.ERROR_000
        respuesta = dict()
        respuesta['identificador'] = dict()
        respuesta['identificador']['id_registro'] = data['identificador']['id_registro']
        respuesta['identificador']['id_usuario'] = data['identificador']['id_usuario']
        respuesta['identificador']['token'] = data['identificador']['token']
        respuesta['error'] = dict()
        respuesta['error']['code'] = error['code']
        respuesta['error']['descripcion'] = error['descripcion']

        # genera un registro en el log
        rtnlog = genera_log(db, idcontribuyente, **respuesta)

        return json.dumps(respuesta)

    except Exception as e:
        print(f'Error - set_pago {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# ES LA RUTA PARA CREAR LA CONEXION
@automotor_api.route('/crearconexion/<int:id_registro>/<int:id_usuario>', methods=['GET'])
def crearconexion(id_registro, id_usuario):

    try:
        """
        Realiza el procedimiento de la conexion al sistema de api de la municipalidad
        :param id_registro:
        :param id_usuario:
        :return: un json con  la respuesta
        """
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # SI EL METODO ES GET
        if request.method == 'GET':
            print(f'Conexion {id_registro} {id_usuario}\n')

            # Obtenemos los datos del json recibidos del cliente
            datos_dict = request.json
            print(datos_dict)

            # verificamos la estructura recibida
            if not controlApiConexion(**datos_dict):
                datos_dict['error'] = api.ERROR_415
                # genera un registro en el log
                rtnlog = genera_log(db, '', **datos_dict)
                print(f'Conexion  {api.ERROR_415}')
                return json.dumps(datos_dict)

            # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
            # Verificamos SI el idusuario del json es igual al id_usuario
            # recibido por parametro
            if datos_dict['idusuario'] == str(id_usuario):
                datos_dict['error'] = api.ERROR_401
                return json.dumps(datos_dict)

            # Si son diferentes es lo correcto
            else:
                datos_dict['jsonidusuario'] = datos_dict['idusuario']
                datos_dict['id_registro'] = id_registro
                datos_dict['id_usuario'] = id_usuario

            # genera un registro en el log
            rtnlog = genera_log(db, '', **datos_dict)

            # Verifica la conexion con los datos del usuario y registro
            # Retorna Error de Validacion o un Token
            return verifcaconexion(db, **datos_dict)

    except Exception as e:
        print(f'Error conexion {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# ES LA RUTA PARA EL PEDIDO DE LA DEUDA
@automotor_api.route('/deuda/<int:id_registro>/<int:id_usuario>', methods=['GET'])
def deuda(id_registro, id_usuario):

    try:
        """
        Obtenemos la deuda del Dominio
        :param id_registro:
        :param id_usuario:
        :return: un json con la respuesta
        """
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # SI EL METODO ES GET
        if request.method == 'GET':
            print(f'Deuda {id_registro} {id_usuario}\n')

            # Obtenemos los datos recibidos del cliente
            datos_dict = request.json

            # verificamos la estructura recibida
            if not controlApiDeuda(**datos_dict):
                datos_dict['error'] = api.ERROR_415
                # genera un registro en el log
                rtnlog = genera_log(db, '', **datos_dict)
                print(f'Obtener Deuda  {api.ERROR_415}')
                return json.dumps(datos_dict)


            # genera un registro en el log
            rtnlog = genera_log(db, '', **datos_dict)

            # Retorna la informacion al Usuario
            return get_deuda(db, **datos_dict)

    except Exception as e:
        print(f'Error deuda {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# ES LA RUTA PARA EL PAGO DE LA DEUDA
@automotor_api.route('/pagodeuda/<int:id_registro>/<int:id_usuario>', methods=['POST'])
def pagodeuda(id_registro, id_usuario):

    try:
        """
        Realiza el pago de la deuda recibida en el json
        :param id_registro:
        :param id_usuario:
        :return: un json con la respuesta
        """
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # SI EL METODO ES POST
        if request.method == 'POST':
            print(f'Pago Deuda {id_registro} {id_usuario}\n')


            # Obtenemos los datos recibidos del cliente
            datos_dict = request.json

            # verificamos la estructura recibida
            if not controlApiPagoDeuda(**datos_dict):
                datos_dict['error'] = api.ERROR_415
                # genera un registro en el log
                print(f'Pago Deudas  {api.ERROR_415}')
                rtnlog = genera_log(db, '', **datos_dict)
                return json.dumps(datos_dict)

            # genera un registro en el log
            rtnlog = genera_log(db, '', **datos_dict)


            # Retorna la informacion al Usuario
            return set_pago(db, **datos_dict)
    except Exception as e:
        print(f'Pago deuda {e}')

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# ES LA RUTA PARA LA CANCELACION DE LA DEUDA
@automotor_api.route('/cancelaciondeuda/<int:id_registro>/<int:id_usuario>', methods=['POST'])
def cancelaciondeuda(id_registro, id_usuario):

    try:
        """
        La cancela de la deuda es cancelar totalmente la deuda del dominio
        :param id_registro:
        :param id_usuario:
        :return: un Json con la respuesta
        """
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # SI EL METODO ES POST
        if request.method == 'POST':
            print(f'Cancelacion Deuda {id_registro} {id_usuario}\n')

            # Obtenemos los datos recibidos del cliente
            datos_dict = request.json

            # verificamos la estructura recibida
            if not  controlApiPagoDeuda(**datos_dict):
                datos_dict['error'] = api.ERROR_415
                # genera un registro en el log
                print(f'Cancelacion Deuda  {api.ERROR_415}')
                rtnlog = genera_log(db, '', **datos_dict)
                return json.dumps(datos_dict)

            # genera un registro en el log
            rtnlog = genera_log(db, '', **datos_dict)

            # Retorna la informacion al Usuario
            return set_pago(db, **datos_dict)

    except Exception as e:
        print(f'Cancelacion deuda {e}')
