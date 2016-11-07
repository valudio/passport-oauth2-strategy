import * as passport from 'passport-strategy';

export interface IStrategyOptions {
  passReqToCallBack?: boolean;
}

export interface IRequest {
  body: Object;
}

export class Strategy extends passport.Strategy {

  public name: string;
  private _verify: Function;
  private _passReqToCallBack: boolean;

  constructor(options: Function | IStrategyOptions, verify?: Function) {
    super();
    if (typeof options === 'function') {
      verify = options;
      options = {};
    }
    if (!verify) throw new Error('Passport-oauth2-strategy requires a verify function');
    this.name = 'passport-oauth2-strategy';
    this._verify = verify;
    this._passReqToCallBack = options.passReqToCallBack;
  }

  public authenticate(req: IRequest) {
    if (!req.body) { return this.fail(0); }
    
    const grant = req.body['grant_type'];
    const clientId = req.body['client_id'];
    const clientSecret = req.body['client_secret'];

    if (!clientId || (grant === 'authorization_code' && !clientSecret)) {
      return this.fail(0);
    }
  
    const self = this;
    function verified(err, client, info){
      if (err) { return self.error(err); }
      if (!client) { return self.fail(0); }
      self.success(client, info);
    }

    if(this._passReqToCallBack) {
      this._verify(req, clientId, clientSecret, verified);
    }else {
      this._verify(clientId, clientSecret, verified);
    }
  }
}

