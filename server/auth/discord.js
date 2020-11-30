// @flow
import addHours from "date-fns/add_hours";
import fetch from "isomorphic-fetch";
import Router from "koa-router";
import Sequelize from "sequelize";
import { discordAuth } from "../../shared/utils/routeHelpers";
import { InvalidRequestError } from "../errors";
import auth from "../middlewares/authentication";
import { User, Team } from "../models";
import { getCookieDomain } from "../utils/domains";

const Op = Sequelize.Op;
const router = new Router();

// start the oauth process and redirect user to Slack
router.get("discord", async (ctx) => {
  const state = Math.random().toString(36).substring(7);

  ctx.cookies.set("state", state, {
    httpOnly: false,
    expires: addHours(new Date(), 1),
    domain: getCookieDomain(ctx.request.hostname),
  });
  ctx.redirect(discordAuth(state));
});

// signin callback from Slack
router.get("discord.callback", auth({ required: false }), async (ctx) => {
  const { code, error, state } = ctx.request.query;
  ctx.assertPresent(code || error, "code is required");
  ctx.assertPresent(state, "state is required");

  if (state !== ctx.cookies.get("state")) {
    ctx.redirect("/?notice=auth-error&error=state_mismatch");
    return;
  }
  if (error) {
    ctx.redirect(`/?notice=auth-error&error=${error}`);
    return;
  }

  const tokenData = await discordToken(code);
  const token = tokenData.access_token;
  const userData = await discordProfile(token);

  const [team, isFirstUser] = await Team.findOrCreate({
    where: {
      slackId: userData.id,
    },
    defaults: {
      name: userData.username,
      // avatarUrl: '',
    },
  });

  try {
    const [user, isFirstSignin] = await User.findOrCreate({
      where: {
        [Op.or]: [
          {
            service: "discord",
            serviceId: userData.id,
          },
          {
            service: { [Op.eq]: null },
            email: userData.email,
          },
        ],
        teamId: team.id,
      },
      defaults: {
        service: "discord",
        serviceId: userData.id,
        name: userData.username,
        email: userData.email,
        isAdmin: isFirstUser,
        // avatarUrl: data.user.image_192,
      },
    });

    // update the user with fresh details if they just accepted an invite
    if (!user.serviceId || !user.service) {
      await user.update({
        service: "discord",
        serviceId: userData.id,
        // avatarUrl: data.user.image_192,
      });
    }

    // update email address if it's changed in Slack
    if (!isFirstSignin && userData.email !== user.email) {
      await user.update({ email: userData.email });
    }

    if (isFirstUser) {
      await team.provisionFirstCollection(user.id);
      // await team.provisionSubdomain(data.team.domain);
    }

    // set cookies on response and redirect to team subdomain
    ctx.signIn(user, team, "slack", isFirstSignin);
  } catch (err) {
    if (err instanceof Sequelize.UniqueConstraintError) {
      const exists = await User.findOne({
        where: {
          service: "email",
          email: userData.email,
          teamId: team.id,
        },
      });

      if (exists) {
        ctx.redirect(`${team.url}?notice=email-auth-required`);
      } else {
        ctx.redirect(`${team.url}?notice=auth-error`);
      }

      return;
    }

    throw err;
  }
});

async function discordToken(
  code: string
): Promise<{|
  access_token: string,
  token_type: string,
  expires_in: number,
  refresh_token: string,
  scope: string,
|}> {
  const body = {
    client_id: process.env.DISCORD_CLIENT_ID,
    client_secret: process.env.DISCORD_CLIENT_SECRET,
    grant_type: "authorization_code",
    redirect_uri: `${process.env.URL}/auth/discord.callback`,
    code,
    scope: "identify email",
  };

  let data;
  try {
    const response = await fetch(process.env.DISCORD_TOKEN_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    data = await response.json();
  } catch (err) {
    throw new InvalidRequestError(err.message);
  }
  if (!data.ok) throw new InvalidRequestError(data.error);

  return data;
}

async function discordProfile(
  token: string
): Promise<{|
  id: string,
  username: string,
  discriminator: string,
  avatar: string,
  verified: boolean,
  email: string,
  flags: number,
  premium_type: number,
  public_flags: number,
|}> {
  let data;

  try {
    const response = await fetch(`https://discordapp.com/api/users/@me`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
    data = await response.json();
  } catch (err) {
    throw new InvalidRequestError(err.message);
  }
  if (!data.ok) throw new InvalidRequestError(data.error);

  return data;
}

export default router;
