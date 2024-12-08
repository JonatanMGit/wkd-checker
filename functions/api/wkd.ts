import { validateEmail, processEmail } from '../../lib/wkd-lib';

export const onRequest: PagesFunction = async (context) => {
    if (context.request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
    }

    const contentType = context.request.headers.get("content-type");
    let email: string | null = null;

    try {
        if (contentType === "application/x-www-form-urlencoded") {
            const formData = await context.request.formData();
            email = formData.get("email")?.toString() || null;
        } else if (contentType === "application/json") {
            const body: { email: string } = await context.request.json();
            email = body.email;
        }
    } catch {
        return new Response("Invalid Request", { status: 400 });
    }

    if (!email || !validateEmail(email)) {
        return new Response("Invalid email", { status: 400 });
    }

    const result = await processEmail(email);

    return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json" }
    });
};
